<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Tcloud</title>
</head>
<body>

<#if message?? && message?has_content>
<p>${message}</p>
</#if>

Tclouds-service : <br>
<#if tclouds?? && tclouds?has_content>
    <#list tclouds as tcloud>
        <#if tcloud.tcloudName?has_content>
           ${tcloud.id} - ${tcloud.tcloudName}<br>
        </#if>
    </#list>
 </#if>

</body>
</html>