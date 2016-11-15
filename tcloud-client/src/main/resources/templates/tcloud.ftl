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
           <span id="tcloud_${tcloud.id?html}" class="<#if tcloud_index%2=0>even<#else>odd</#if>">
            ${tcloud.id?html} - ${tcloud.tcloudName?html}
           </span><br>
        </#if>
    </#list>
 </#if>

</body>
</html>