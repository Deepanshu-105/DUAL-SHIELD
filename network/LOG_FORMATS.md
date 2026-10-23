# Log formats (for M4 dashboard parsing)

All logs live inside the containers. Times are Unix seconds with milliseconds unless noted.

## target:/var/log/parser_block.log
One line per IP blocked by the SSH parser.
    PARSER_BLOCK ip=172.30.0.12 ts=1792751005.537
Regex: `^PARSER_BLOCK ip=(\S+) ts=([\d.]+)$`

## peer:/var/log/peer_block.log
One line per IP the peer blocked after the chain event (Layer 2, immunisation).
    PEER_BLOCK ip=172.30.0.12 ts=1792751006.019
Regex: `^PEER_BLOCK ip=(\S+) ts=([\d.]+)$`
Block time on the peer = PEER_BLOCK ts - PARSER_BLOCK ts for the same ip.

## target:/var/log/metrics.log
    METRIC lookup_ms=0.004
    METRIC drop_ms=4.362
Regex: `^METRIC (lookup_ms|drop_ms)=([\d.]+)$`
drop_ms = time from the 3rd failed login to the ipset add (local drop).

## target:/var/log/parser.out (human readable, not for parsing)
    [FAIL] 172.30.0.12 -> 4 failure(s) in last 5s  hassh=015322ee8471fa8338c558a918183b11  tor=yes
    [PARSER_BLOCK] PARSER_BLOCK ip=172.30.0.12 ts=...
    [CHAIN] reported 172.30.0.12
    [HASSH] 172.30.0.12 -> 015322ee8471fa8338c558a918183b11

## ipsets (live state)
    docker exec target ipset list city_blacklist
    docker exec peer   ipset list city_blacklist
Members appear after the line `Members:`, one IP per line. This is what /api/blocked reads.

## Rules
- Never truncate /var/log/auth.log while the parser runs (it loses its read position); stop the parser first.
- The source IP in auth.log is the real attacker address (172.30.0.12 for the attacker container).
