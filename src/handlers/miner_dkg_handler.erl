%%%-------------------------------------------------------------------
%% @doc
%% == miner dkg_handler ==
%% @end
%%%-------------------------------------------------------------------
-module(miner_dkg_handler).

-behavior(relcast).

-export([init/1, handle_message/3, handle_command/2, callback_message/3, serialize/1, deserialize/1, restore/2]).

-record(state,
        {
         n :: non_neg_integer(),
         f :: non_neg_integer(),
         t :: non_neg_integer(),
         id :: non_neg_integer(),
         dkg :: dkg_hybriddkg:dkg() | dkg_hybriddkg:serialized_dkg(),
         curve :: atom(),
         g1 :: erlang_pbc:element() | binary(),
         g2 :: erlang_pbc:element() | binary(),
         privkey :: undefined | tpke_privkey:privkey() | tpke_privkey:privkey_serialized(),
         members = [] :: [libp2p_crypto:address()],
         donemod :: atom(),
         donefun :: atom(),
         done_called = false :: boolean(),
         sent_conf = false :: boolean(),
         timer :: undefined | pid()
        }).

init([Members, Id, N, F, T, Curve, {DoneMod, DoneFun}]) when is_atom(DoneMod), is_atom(DoneFun) ->
    {G1, G2} = generate(Curve, Members),
    DKG = dkg_hybriddkg:init(Id, N, F, T, G1, G2, 0, [{callback, true}]),
    lager:info("DKG~p started", [Id]),
    {ok, #state{n=N,
                id=Id,
                f=F,
                t=T,
                g1=G1, g2=G2,
                curve=Curve,
                dkg=DKG,
                donemod=DoneMod, donefun=DoneFun,
                members=Members}}.

handle_command(start, State) ->
    {NewDKG, {send, Msgs}} = dkg_hybriddkg:start(State#state.dkg),
    {reply, ok, fixup_msgs(Msgs), State#state{dkg=NewDKG}};
handle_command({status, Ref, Worker}, State) ->
    Map = dkg_hybriddkg:status(State#state.dkg),
    Worker ! {Ref, maps:merge(#{
                     id => State#state.id,
                     members => State#state.members,
                     signatures_required => State#state.signatures_required,
                     signatures => length(State#state.signatures),
                     sent_conf => State#state.sent_conf
                    }, Map)},
    {reply, ok, ignore};
handle_command(timeout, State) ->
    case dkg_hybriddkg:handle_msg(State#state.dkg, State#state.id, timeout) of
        {_DKG, ok} ->
            {reply, ok, [], State#state{timer=undefined}};
        {NewDKG, {send, Msgs}} ->
            {reply, ok, fixup_msgs(Msgs), State#state{dkg=NewDKG, timer=undefined}}
    end.

handle_message(BinMsg, Index, State=#state{n = N, t = T,
                                           curve = Curve,
                                           g1 = G1, g2 = G2,
                                           members = Members,
                                           sigmod = SigMod, sigfun = SigFun,
                                           donemod = DoneMod, donefun = DoneFun}) ->
    Msg = binary_to_term(BinMsg),
    lager:debug("DKG input ~s from ~p", [fakecast:print_message(Msg), Index]),
    case dkg_hybriddkg:handle_msg(State#state.dkg, Index, Msg) of
        %% NOTE: We cover all possible return values from handle_msg hence
        %% eliminating the need for a final catch-all clause
        {_, ignore} ->
            ignore;
        {NewDKG, ok} ->
            {State#state{dkg=NewDKG}, []};
        {NewDKG, {send, Msgs}} ->
            {State#state{dkg=NewDKG}, fixup_msgs(Msgs)};
        {NewDKG, start_timer} ->
            case State#state.timer of
                undefined -> ok;
                OldTimer ->
                    OldTimer  ! cancel
            end,
            Parent = self(),
            Pid = spawn(fun() ->
                                receive
                                    cancel -> ok
                                after 300000 ->
                                        libp2p_group_relcast_server:handle_input(Parent, timeout)
                                end
                        end),
            {State#state{dkg=NewDKG, timer=Pid}, []};
        {NewDKG, {result, {Shard, VK, VKs}}} ->
            lager:info("Completed DKG ~p", [State#state.id]),
            PrivateKey = tpke_privkey:init(tpke_pubkey:init(N, T, G1, G2, VK, VKs, Curve), Shard, State#state.id - 1),
            ok = DoneMod:DoneFun(Members, PrivateKey),
            %% stop the handler
            {State#state{done_called = true}, [{stop, 60000}]}
    end.

callback_message(Actor, Message, _State) ->
    case binary_to_term(Message) of
        {Id, {send, {Session, SerializedCommitment, Shares}}} ->
            term_to_binary({Id, {send, {Session, SerializedCommitment, lists:nth(Actor, Shares)}}});
        {Id, {echo, {Session, SerializedCommitment, Shares}}} ->
            term_to_binary({Id, {echo, {Session, SerializedCommitment, lists:nth(Actor, Shares)}}});
        {Id, {ready, {Session, SerializedCommitment, Shares}}} ->
            term_to_binary({Id, {ready, {Session, SerializedCommitment, lists:nth(Actor, Shares)}}})
    end.

%% helper functions
serialize(State) ->
    SerializedDKG = dkg_hybriddkg:serialize(State#state.dkg),
    G1 = erlang_pbc:element_to_binary(State#state.g1),
    G2 = erlang_pbc:element_to_binary(State#state.g2),
    PrivKey = case State#state.privkey of
                  undefined ->
                      undefined;
                  Other ->
                      tpke_privkey:serialize(Other)
              end,
    term_to_binary(State#state{dkg=SerializedDKG, g1=G1, g2=G2, privkey=PrivKey}, [compressed]).

deserialize(BinState) ->
    State = binary_to_term(BinState),
    Group = erlang_pbc:group_new(State#state.curve),
    G1 = erlang_pbc:binary_to_element(Group, State#state.g1),
    G2 = erlang_pbc:binary_to_element(Group, State#state.g2),
    DKG = dkg_hybriddkg:deserialize(State#state.dkg, G1),
    PrivKey = case State#state.privkey of
        undefined ->
            undefined;
        Other ->
            tpke_privkey:deserialize(Other)
    end,
    State#state{dkg=DKG, g1=G1, g2=G2, privkey=PrivKey}.

restore(OldState, _NewState) ->
    {ok, OldState}.

fixup_msgs(Msgs) ->
    lists:map(fun({unicast, J, NextMsg}) ->
                      {unicast, J, term_to_binary(NextMsg)};
                 ({multicast, NextMsg}) ->
                      {multicast, term_to_binary(NextMsg)};
                 ({callback, NextMsg}) ->
                      {callback, term_to_binary(NextMsg)}
              end, Msgs).

%% ==================================================================
%% Internal functions
%% ==================================================================
generate(Curve, Members) ->
    Group = erlang_pbc:group_new(Curve),
    G1 = erlang_pbc:element_from_hash(erlang_pbc:element_new('G1', Group), term_to_binary(Members)),
    G2 = case erlang_pbc:pairing_is_symmetric(Group) of
             true -> G1;
             %% XXX breaks for asymmetric curve
             false -> erlang_pbc:element_from_hash(erlang_pbc:element_new('G2', Group), crypto:strong_rand_bytes(32))
         end,
    {G1, G2}.
