Event log on the DCs

In the Default Domain Controllers Policy under Advanced Audit Policy → Account Management, set Audit Security Group Management and Audit User Account Management to Success.
Then in Zabbix (eventlog only works as an active item, and it must run on every DC, because the event is only logged on the DC where the change happened):

  eventlog[Security,,,,^(4728|4729|4732|4733|4756|4757)$,,skip]

Trigger: find(/DC01/eventlog[...],,"regexp",".")=1, with nodata() for recovery or manual close.

For primaryGroupID changes, event 4738 (user account changed) is relevant, but it’s very noisy. Filter on the field:

  eventlog[Security,"Primary Group ID:\s+\d",,,^4738$,,skip]

On a Dutch-language Windows Server the field name is different; check a real 4738 event and adjust the regex.
