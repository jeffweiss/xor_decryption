-module (solution).
-export ([ciphertext/0,bruteforce/1]).
-export ([start/0]).
-export ([decode/3]).

csv_to_int_list(Numbers) ->
    Tokens = string:tokens(Numbers, ","),
    [list_to_integer(N) || N <- Tokens].

int_list_to_csv(Numbers) ->
    string:join([integer_to_list(N) || N <- Numbers], ",").

valid_chars(extended) ->
    valid_chars(basic) ++ "/;:|`~~@\\#$%^&*_=+{}<>[]";
valid_chars(basic) ->
    lists:seq($a,$z) ++ lists:seq($A, $Z) ++ lists:seq($0, $9) ++ " !.?,-()'\"\t\r\n".
        
keyspace() ->
    Letters = lists:seq($a, $z),
    [ [A] ++ [B] ++ [C] ++ [D] || A <- Letters, B <- Letters, C <- Letters, D <- Letters].

progress_display(Fun, TimeStart, KeyspaceSize, Args) ->
    [_,{Key,Index},_] = Args,
    if
        Index rem 2500 == 0 ->
            Microseconds = timer:now_diff(now(), TimeStart),
            KeysPerSecond = Index / (Microseconds/1000000.0),
            ETA = (KeyspaceSize - Index) / KeysPerSecond,
            io:format("\t~s -- ~.2f keys/s -- ETA ~.2f seconds     \r", [Key, KeysPerSecond, ETA]);
        true ->
            ok
    end,
    apply(solution, Fun, Args).

allowed_invalid_chars() ->
    3.

decode(_Ints, {_Key,_Index}, _ValidChars) ->
    decode(_Ints, _Key, {_Key,_Index}, _ValidChars, allowed_invalid_chars(), 0, []).

decode(_, _, {OrigKey,_}, _, AllowableBad, AccumulatedBad, _) when AllowableBad =< AccumulatedBad ->
    {OrigKey, bad};
decode([], _, {OrigKey,_}, _, _, _, AcculatedResults) ->
    {OrigKey, AcculatedResults};
decode([I|Is], [K|Ks], {OrigKey,Index}, Valid, AllowableBad, AccumulatedBad, AcculatedResults) ->
    CipherChar = I bxor K,
    Increment = case lists:member(CipherChar, Valid) of
        true ->
            0;
        false ->
            1
    end,
    decode(Is, Ks ++ [K], {OrigKey,Index}, Valid, AllowableBad, AccumulatedBad + Increment, AcculatedResults  ++ [CipherChar]).

decode_and_validate(Cipher, KeyspaceWithIndex, ValidChars) ->
    io:format("valid chars: ~s~n", [ValidChars]),
    StartTime = now(),
    KeyspaceSize = length(KeyspaceWithIndex),
    PostDictionaryCheck = [ dictionary_check(X) || X <- [ progress_display(decode, StartTime, KeyspaceSize, [Cipher, K, ValidChars]) || K <- KeyspaceWithIndex ]],
    io:format("~n"),
    lists:filter(fun({_,X}) -> not(X == bad) end, PostDictionaryCheck).
    
display({Key, Plaintext}) ->
    io:format("CIPHER KEY: ~s~nPLAIN TEXT:~n~s~n", [Key, Plaintext]).

start() ->
    bruteforce(ciphertext()).

bruteforce(Cipher) ->
    Keyspace = keyspace(),
    KeyspaceWithIndex = lists:zip(Keyspace, lists:seq(1, length(Keyspace))),
    io:format("number of possible keys: ~B~n", [length(Keyspace)]),
    Valid = valid_chars(basic),
    Results = decode_and_validate(Cipher, KeyspaceWithIndex, Valid),
    Display = if
        length(Results) == 0 ->
            io:format("No suitable plaintext found, expanding set of valid characters~n"),
            ExtendedValidChars = valid_chars(extended),
            decode_and_validate(Cipher, KeyspaceWithIndex, ExtendedValidChars);
        true ->
            Results
    end,
    lists:foreach(fun(X)->display(X) end, Display).

dictionary_check({_Key,bad}) ->
    {_Key, bad};
dictionary_check({_Key,Text}) ->
    Words = string:tokens(Text, "~~1!2@3#4$5%6^7&8*9(0)-_=+[{}];:'\",<.>/? \t\r\n"),
    case lists:member("the", Words) of
        true ->
            {_Key,Text};
        false ->
            {_Key, bad}
    end.

ciphertext() ->
    [35,1,7,5,21,73,33,5,80,48,1,30,80,42,28,10,10,16,78,47,25,8,3,4,30,13,78,67,57,68,56,66,122,99,60,14,29,12,3,9,21,27,78,28,24,12,0,75,9,6,27,75,7,12,28,14,80,16,1,30,30,14,66,75,9,6,27,75,3,1,1,5,21,73,2,2,27,12,78,31,24,12,78,24,5,7,64,97,35,1,7,5,21,73,1,5,80,16,1,30,80,10,28,10,10,16,78,15,25,8,3,4,30,13,64,97,62,6,25,75,4,1,11,25,21,78,29,75,17,73,2,4,31,2,78,2,30,73,23,4,5,27,78,14,9,12,29,71,80,5,7,0,21,73,12,7,17,10,5,75,24,6,2,14,3,73,7,5,80,29,6,14,80,26,5,18,94,99,61,3,25,7,11,75,31,7,78,18,31,28,78,8,2,8,20,18,80,13,7,10,29,6,0,15,94,99,55,4,5,73,25,14,2,12,78,8,17,28,9,3,4,73,1,5,80,29,6,14,80,10,28,4,3,26,8,2,2,12,78,4,22,73,13,3,25,5,10,3,31,6,10,75,17,7,10,75,3,29,15,25,20,6,3,71,80,99,12,7,31,30,0,75,31,7,78,31,24,12,78,24,4,12,11,7,80,11,28,14,21,19,11,69,122,42,1,6,21,73,1,5,80,16,1,30,80,29,15,25,23,12,26,75,22,6,28,75,22,8,28,10,7,8,23,75,28,8,27,12,24,29,11,25,92,73,100,8,31,4,11,75,31,7,78,18,31,28,78,24,4,27,15,5,23,12,28,71,80,16,1,30,80,5,11,12,21,7,10,71,80,16,1,30,80,4,15,25,4,16,28,71,80,8,0,15,80,26,6,2,30,12,79,97,41,6,27,75,2,12,15,8,24,12,10,75,22,6,28,75,4,1,11,75,3,12,13,25,21,29,78,31,31,6,78,24,31,6,0,71,80,16,1,30,80,10,28,2,21,13,78,13,31,27,78,31,24,12,78,6,31,6,0,69,122,58,6,2,30,12,78,4,30,73,23,4,5,73,13,25,17,19,23,75,20,0,15,6,31,7,10,69,122,61,6,25,21,8,26,14,30,12,10,75,18,16,78,24,24,8,10,4,7,26,78,10,4,73,0,2,23,1,26,71,80,8,0,15,80,12,22,27,31,26,11,15,80,0,0,75,4,1,11,75,28,0,9,3,4,71,100,56,24,0,0,14,80,6,0,75,9,6,27,75,19,27,15,17,9,73,10,2,17,4,1,5,20,71,100,60,21,5,2,75,9,6,27,75,7,6,28,14,80,6,27,31,80,16,1,30,2,73,25,14,28,10,1,6,21,73,25,2,4,1,78,25,17,7,10,4,29,73,30,25,21,10,7,24,25,6,0,71,122,27,1,15,21,73,1,5,80,29,6,14,80,26,26,14,21,5,78,9,2,12,11,17,21,71,100,40,31,4,11,75,31,7,78,18,31,28,78,25,17,31,11,25,92,73,23,4,5,73,29,14,21,27,78,4,22,73,24,2,3,0,1,5,3,69,78,97,19,6,3,14,80,6,0,75,9,6,27,75,0,8,7,5,4,12,28,71,80,16,1,30,80,25,7,27,21,27,66,75,9,6,27,75,0,27,7,24,31,7,11,25,92,73,15,5,20,73,29,3,25,7,11,74,122].
