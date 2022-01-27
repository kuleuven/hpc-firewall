Rules to add X-Orig-Forwarded-For header:

```
add rewrite action WEB_P_RWR_ACT_Insert_XOrigForwardedFor_Header insert_http_header X-Orig-Forwarded-For "HTTP.REQ.HEADER(\"X-Forwarded-For\")"
add rewrite policy WEB_P_RWR_POL_Insert_XOrigForwardedFor_Header "HTTP.REQ.HEADER(\"X-Forwarded-For\").EXISTS"  WEB_P_RWR_ACT_Insert_XOrigForwardedFor_Header 
bind cs vserver WEB_P_CSVSRV_CONTAINER_firewall.hpc.kuleuven.be_HTTPS -policyName WEB_P_RWR_POL_Insert_XOrigForwardedFor_Header -priority 200 -gotoPriorityExpression NEXT -type REQUEST
bind cs vserver WEB-6_P_CSVSRV_CONTAINER_firewall.hpc.kuleuven.be_HTTPS -policyName WEB_P_RWR_POL_Insert_XOrigForwardedFor_Header -priority 200 -gotoPriorityExpression NEXT -type REQUEST
```
