local dns = require "dns"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

---
-- @usage
-- nmap -sU -p 53 --script=dns-query <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 53/udp open  domain  udp-response
-- |_dns-query: IP

hostrule = function(host)
    return true
end


action = function(host)
    status, result = dns.query("learn2018.tsinghua.edu.cn", {host=host.ip, port=53, tries=0, norecurse=false, timeout=250})

    if status then
        return result
    else
        return
    end
end
