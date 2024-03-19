<p align="center">
<img src="Broadcom-vmware.png" width="300" alt="Online Boutique" />
</p>

### CURD functionality of  user,roles and other resources via API for TAS(cloud foundry)

<p align="center">
<img src="api-flow.png" width="1000" alt="Online Boutique" />
</p>

```
curl -k https://uaa.<SYSTEM-DOMAIN>/oauth/token -u "admin:XXXXXXXXXXXXXXXXXXX" -d grant_type=client_credentials
```
```
{"access_token":"XXXXXXXXXXXXXXXXXX","token_type":"bearer","expires_in":43199,"scope":"clients.read password.write clients.secret clients.write uaa.admin scim.write scim.read","jti":"65641e18a12d4174aeba272f3b38e528"}%
```
####
```
uaac token client get admin -s XXXXXXXXXXXXXXXXXXX
WARNING: Decoding token without verifying it was signed by its authoring UAA
```
```
Successfully fetched token via client credentials grant.
Target: https://uaa.<SYSTEM-DOMAIN>
Context: admin, from client admin
```
#### Creating a Admin Client
```
uaac client add admin-client -s admin-client  --authorized_grant_types client_credentials --scope cloud_controller.admin,clients.read,password.write,clients.secret,clients.write,uaa.admin,scim.write,scim.read --authorities cloud_controller.admin,clients.read,password.write,clients.secret,clients.write,uaa.admin,scim.write,scim.read
```
```
  scope: clients.read password.write clients.secret clients.write uaa.admin scim.write scim.read cloud_controller.admin
  client_id: admin-client
  resource_ids: none
  authorized_grant_types: client_credentials
  autoapprove:
  authorities: clients.read password.write clients.secret clients.write uaa.admin scim.write scim.read cloud_controller.admin
  name: admin-client
  required_user_groups:
  lastmodified: 1710054787000
  id: admin-client
````

```
curl -k https://uaa.<SYSTEM-DOMAIN>/oauth/token -u "admin-client:admin-client" -d grant_type=client_credentials
```

#### Fetch token
```
curl -k https://uaa.<SYS-DOMAIN>/oauth/token -u "admin:XXXXXXXXXXXXXXXXXXXX" -d grant_type=client_credentials
```
#### Sample output
```
{"access_token":"XXXXXXXXXXXXXXXXXXXX","token_type":"bearer","expires_in":43199,"scope":"clients.read password.write clients.secret clients.write uaa.admin scim.write scim.read","jti":"aded8cfd29ca42851"}%
```

#### Creating user in UAA database for TAS.
```
curl -k 'https://uaa.<SYS-DOMAIN>/Users' -i -X POST \
   -H 'Accept: application/json' \
   -H 'Authorization: Bearer XXXXXXXXXXXXXXXXXXXX' \
   -H 'Content-Type: application/json' \
   -d '{
 "externalId" : "test-user",
 "meta" : {
   "version" : 0,
   "created" : "2024-03-08T05:49:51.444Z"
 },
 "userName" : "arul@test.org",
 "name" : {
   "formatted" : "given name family name",
   "familyName" : "vannala",
   "givenName" : "arul"
 },
 "emails" : [ {
   "value" : "NdjtyD@test.org",
   "primary" : true
 } ],
 "phoneNumbers" : [ {
   "value" : "5555555555"
 } ],
 "active" : true,
 "verified" : true,
 "origin" : "",
 "password" : "secret",
 "schemas" : [ "urn:scim:schemas:core:1.0" ]
}'
HTTP/2 201
cache-control: no-cache, no-store, max-age=0, must-revalidate
content-security-policy: script-src 'self'
content-type: application/json
date: Sat, 09 Mar 2024 17:55:52 GMT
etag: "0"
expires: 0
pragma: no-cache
strict-transport-security: max-age=31536000 ; includeSubDomains
x-content-type-options: nosniff
x-frame-options: DENY
x-vcap-request-id: 08718a44-2f14-4d96-72c1-86f083e5dc9a
x-xss-protection: 1; mode=block
```
#### Sample output
```
{"id":"5e8e0e75-95dc-42a9-96c2-d14d35001835","externalId":"test-user","meta":{"version":0,"created":"2024-03-09T17:55:53.000Z","lastModified":"2024-03-09T17:55:53.000Z"},"userName":"arul@test.org","name":{"familyName":"vannala","givenName":"arul"},"emails":[{"value":"NdjtyD@test.org","primary":false}],"groups":[{"value":"d876e9f3-86f0-47c1-bc72-167b927bcb55","display":"cloud_controller.write","type":"DIRECT"},{"value":"2d5b0b94-e0f4-4122-b621-6c9344f331e0","display":"password.write","type":"DIRECT"},{"value":"ed2bc504-63cc-4bab-ba87-71ccac044a41","display":"oauth.approvals","type":"DIRECT"},{"value":"ef62f9e2-6f95-4757-b371-07da68d41785","display":"profile","type":"DIRECT"},{"value":"b2637f98-e727-4008-bae5-d583773657e8","display":"user_attributes","type":"DIRECT"},{"value":"813d2454-2113-4e5c-ba70-da039473a876","display":"cloud_controller_service_permissions.read","type":"DIRECT"},{"value":"113ad67f-dfac-43dc-ad41-e55caf87b117","display":"roles","type":"DIRECT"},{"value":"31abef3c-7061-4d55-959a-d6bc15aeac18","display":"uaa.user","type":"DIRECT"},{"value":"a196b0b4-678b-4733-a8df-8dce8af4c0bb","display":"uaa.offline_token","type":"DIRECT"},{"value":"e147572b-6a75-447f-99e0-0e1549e3f948","display":"cloud_controller.read","type":"DIRECT"},{"value":"0810b436-d24a-4b69-89a2-82bcf2a8d2a7","display":"notification_preferences.write","type":"DIRECT"},{"value":"e50b9f20-8424-4006-80aa-3a82bdae71f3","display":"notification_preferences.read","type":"DIRECT"},{"value":"8a56c942-db7a-4d1d-b231-412b937acbd2","display":"actuator.read","type":"DIRECT"},{"value":"d032588c-1260-4835-ad27-1179081568a0","display":"scim.me","type":"DIRECT"},{"value":"fd925f3c-09a2-4eed-96e3-d60f30e8cfce","display":"approvals.me","type":"DIRECT"},{"value":"7e9f8634-27bf-4c1e-bc64-1f85cbe18d72","display":"openid","type":"DIRECT"},{"value":"2a89cb0b-c279-434a-a98a-4298375073fb","display":"cloud_controller.user","type":"DIRECT"}],"approvals":[],"phoneNumbers":[{"value":"5555555555"}],"active":true,"verified":true,"origin":"uaa","zoneId":"uaa","passwordLastModified":"2024-03-09T17:55:52.000Z","schemas":["urn:scim:schemas:core:1.0"]}%
```

### Query to verify roles
```
cf curl "/v3/roles?order_by=%2Bcreated_at&page=1&per_page=500" | jq  '.resources[] | "\(.type)  \(.relationships.user.data.guid) \(.relationships.organization.data.guid) \(.relationships.space.data.guid)" ' | column -t
```
#### Update User info
```
curl -k "https://api.<SYSTEM-DOMAIN>/v3/users/2a89cb0b-c279-434a-a98a-4298375073fb" \
  -X PATCH \
  -H "Authorization: bearer XXXXXXXXXXXXXXXXXXX" \
  -H "Content-type: application/json" \
  -d '{"guid":"2a89cb0b-c279-434a-a98a-4298375073fb","created_at":"2024-03-09T18:37:05Z","updated_at":"2024-03-09T18:37:05Z","username":"arul@test.org","presentation_name":"2a89cb0b-c279-434a-a98a-4298375073fb","origin":null,"metadata":{"labels":{},"annotations":{}},"links":{"self":{"href":"https://api.<SYSTEM-DOMAIN>/v3/users/2a89cb0b-c279-434a-a98a-4298375073fb"}'
{"errors":[{"detail":"Request invalid due to parse error: invalid request body","title":"CF-MessageParseError","code":1001}]}%
```
#### Create roles info
```
curl -k "https://api.<SYSTEM-DOMAIN>/v3/roles" \
  -X POST \
  -H "Authorization: bearer XXXXXXXXXXXXXXXXXXX" \
  -H "Content-type: application/json" \
  -d '{
      "type": "organization_manager",
      "relationships": {
        "user": {
          "data": {
            "guid": "2a89cb0b-c279-434a-a98a-4298375073fb"
          }
        },
        "organization": {
          "data": {
            "guid": "4398c30a-b37e-433a-929c-94750dfbeebd"
          }
        }
      }
    }'
```

```
{"guid":"088f1cde-433c-4a11-a6cd-d3f8cb10c1a9","created_at":"2024-03-09T19:12:35Z","updated_at":"2024-03-09T19:12:35Z","type":"organization_manager","relationships":{"user":{"data":{"guid":"2a89cb0b-c279-434a-a98a-4298375073fb"}},"organization":{"data":{"guid":"4398c30a-b37e-433a-929c-94750dfbeebd"}},"space":{"data":null}},"links":{"self":{"href":"https://api.<SYSTEM-DOMAIN>/v3/roles/088f1cde-433c-4a11-a6cd-d3f8cb10c1a9"},"user":{"href":"https://api.<SYSTEM-DOMAIN>/v3/users/2a89cb0b-c279-434a-a98a-4298375073fb"},"organization":{"href":"https://api.<SYSTEM-DOMAIN>/v3/organizations/4398c30a-b37e-433a-929c-94750dfbeebd"}}
```
#### Creating org users
```
curl -k "https://api.sys.XXXXXX.vmware.com/v3/roles" \
  -X POST \
  -H "Authorization: bearer $token" \
  -H "Content-type: application/json" \
  -d '{
      "type": "organization_user",
      "relationships": {
        "user": {
          "data": {
            "guid": "5e8e0e75-95dc-42a9-96c2-d14d35001835"
          }
        },
        "organization": {
          "data": {
            "guid": "a2ca666d-56ec-4d0f-b4dc-05add44af52d"
          }
        }
      }
    }'
```
```
{"guid":"515f79d4-54a5-4e4e-b919-e5a007bb17e7","created_at":"2024-03-10T08:13:11Z","updated_at":"2024-03-10T08:13:11Z","type":"organization_user","relationships":{"user":{"data":{"guid":"5e8e0e75-95dc-42a9-96c2-d14d35001835"}},"organization":{"data":{"guid":"a2ca666d-56ec-4d0f-b4dc-05add44af52d"}},"space":{"data":null}},"links":{"self":{"href":"https://api.sys.XXXXXX.vmware.com/v3/roles/515f79d4-54a5-4e4e-b919-e5a007bb17e7"},"user":{"href":"https://api.sys.XXXXXX.vmware.com/v3/users/5e8e0e75-95dc-42a9-96c2-d14d35001835"},"organization":{"href":"https://api.sys.XXXXXX.vmware.com/v3/organizations/a2ca666d-56ec-4d0f-b4dc-05add44af52d"}}}%
```
#### Create Space roles
```
curl -k "https://api.sys.XXXXXX.vmware.com/v3/roles" \
  -X POST \
  -H "Authorization: bearer $token" \
  -H "Content-type: application/json" \
  -d '{
      "type": "space_developer",
      "relationships": {
        "user": {
          "data": {
            "guid": "5e8e0e75-95dc-42a9-96c2-d14d35001835"
          }
        },
        "space": {
          "data": {
            "guid": "9a7bec76-6f36-410a-a3b4-eab3fcffc9a2"
          }
        }
      }
    }'
```
```
{"guid":"db8d20f7-fb97-4cc1-a899-0b3741711972","created_at":"2024-03-10T08:13:21Z","updated_at":"2024-03-10T08:13:21Z","type":"space_developer","relationships":{"user":{"data":{"guid":"5e8e0e75-95dc-42a9-96c2-d14d35001835"}},"space":{"data":{"guid":"9a7bec76-6f36-410a-a3b4-eab3fcffc9a2"}},"organization":{"data":null}},"links":{"self":{"href":"https://api.sys.XXXXXX.vmware.com/v3/roles/db8d20f7-fb97-4cc1-a899-0b3741711972"},"user":{"href":"https://api.sys.XXXXXX.vmware.com/v3/users/5e8e0e75-95dc-42a9-96c2-d14d35001835"},"space":{"href":"https://api.sys.XXXXXX.vmware.com/v3/spaces/9a7bec76-6f36-410a-a3b4-eab3fcffc9a2"}}}
```

#### Create Org Quotas
```
curl "https://api.XXXXXX/v3/organization_quotas" \
  -X POST \
  -H "Authorization: bearer [token]" \
  -H "Content-type: application/json" \
  -d '{
    "name": "don-quixote",
    "apps": {
      "total_memory_in_mb": 5120,
      "per_process_memory_in_mb": 1024,
      "log_rate_limit_in_bytes_per_second": 1024,
      "total_instances": 10,
      "per_app_tasks": 5
    },
    "services": {
      "paid_services_allowed": true,
      "total_service_instances": 10,
      "total_service_keys": 20,
    },
    "routes": {
      "total_routes": 8,
      "total_reserved_ports": 4
    },
    "domains": {
      "total_private_domains": 7
    }
  }'
```
