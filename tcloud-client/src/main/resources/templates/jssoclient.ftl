<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="description" content="OAuth2 SSO Client, Rest API jQuery Ajax demo">
    <meta name="keywords" content="JSSO, OAuth2, SSO Client, JWT Token, Rest API, jQuery, Ajax">
    <meta name="author" content="Franck Andriano">

    <title>jQuery Ajax OAuth2 SSO Client, Rest API demo</title>

    <style>
        .results { width: 49.5%; display: inline-block; }
        span.odd { display: inline-block; width: 100%; background: gainsboro; }
        span.even { display: inline-block; width: 100%; background: whitesmoke; }
    </style>

    <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/1.8.0/jquery-1.8.0.min.js" type="text/javascript"></script>

    <script type="text/javascript">
        /**
         * Copyright 2016 the original author or authors
         *
         * Under GPL-3.0 license, see Tcloud-microservice :
         * https://github.com/javaguru/tcloud-microservices
         *
         * Javascript SSO Client OAuth2, dependencies jQuery
         *
         * Author: Franck Andriano on 17/11/2016.
         * Version 1.1
         *
         * JSSOAuth2 use javascript global module pattern with import jQuery for Ajax and extend default options
         */
        var JSSOAuth2 = (function ($) {
            // Config OAuth2 Client and Token
            var defaultOptions = {
                OAuth2Client: {
                    'token_uri': 'http://localhost:9191/uaa/oauth/token',
                    'client': 'acme',
                    'secret': '$2a$10$z/8fQRJlWmEB2jU3kC2rueX0gtVi340X2/bri6U5Yxw4tdHG/vZJS', // encode secret!
                    'username': '',
                    'password': '',
                    'scope': 'read'
                },
                OAuth2Token: {
                    'access_token': '',
                    'refresh_token': '',
                    'expires_in': new Date()
                },
                reloadSSOServices: new Function(),
                loginSSOError: new Function(),
                form_auth: 'form#form_auth',
                debug: false
            };

            var OAuth2Client;
            var OAuth2Token;
            var reloadSSOServices;
            var loginSSOError;
            var form_auth;
            var debug;

            return function(options) {

                this.options = $.extend({}, defaultOptions, options);
                console.log("   Init JSSOAuth2...");

                OAuth2Client = this.options.OAuth2Client;
                OAuth2Token = this.options.OAuth2Token;
                reloadSSOServices = this.options.reloadSSOServices;
                loginSSOError = this.options.loginSSOError;
                form_auth = this.options.form_auth;
                debug = this.options.debug;

                if (debug){
                    console.log("        form_auth: " +this.options.form_auth);
                    console.log("     OAuth2Client: " ,this.options.OAuth2Client);   // log obj!
                    console.log("      OAuth2Token: " ,this.options.OAuth2Token);
                    console.log("reloadSSOServices: " +this.options.reloadSSOServices);
                    console.log("    loginSSOError: " +this.options.loginSSOError);
                }
                return {
                    SSOLogin: function () {
                        ajaxSSOLogin()
                    },
                    SSORefresh: function () {
                        ajaxSSORefresh()
                    },
                    SSOCleanToken: function () {
                        cleanToken()
                    },
                    SSOToken: function () {
                        return getToken()
                    }
                }
            };

            function getToken() {
                return OAuth2Token
            }

            // Call ajax OAuth2 SSO request, attach deferred.promise(jqXHR)!
            function ajaxSSOLogin() {
                var ajax = loginToken().done(storeToken,infoToken).fail(errorServices);
                $.when(ajax).done(function() {
                    if (ajax.status == 200) reloadSSOServices()
                });

                // additional callbacks!
                ajax.fail(function() {
                    // http status 401 Unauthorized: unknown, empty or malformed Bear (Invalid token/Invalid refresh token (expired))
                    // http status 400 Bad request: Invalid grant, Invalid refresh token, unknown or empty!
                    // http status 0 Aborted timeout !?
                    if (ajax.status == 401 || ajax.status == 400) loginSSOError(ajax)
                })
            }

            function ajaxSSORefresh() {
                var ajax = refreshToken().done(storeToken,infoToken).fail(errorServices);
                $.when(ajax).done(function() {
                    if (ajax.status == 200) reloadSSOServices()
                });

                // additional callbacks!
                ajax.fail(function() {
                    // http status 401 Unauthorized: unknown, empty or malformed Bear (Invalid token/Invalid refresh token (expired))
                    // http status 400 Bad request: Invalid grant, Invalid refresh token, unknown or empty!
                    // http status 0 Aborted timeout !?
                    if (ajax.status == 401 || ajax.status == 400) ajaxSSOLogin()
                })
            }

            // Ajax request!
            function loginToken(){
                cleanToken();
                // Form input values username & password
                var $form = $(form_auth);
                if ($form.find('input[name="username"]').length>0  && $form.find('input[name="password"]').length>0) {
                    OAuth2Client.username = $form.find('input[name="username"]').val();
                    OAuth2Client.password = $form.find('input[name="password"]').val();
                }
                var clientToken = btoa(OAuth2Client.client+":"+OAuth2Client.secret);
                var paramsData = {
                    'client_id': OAuth2Client.client,
                    'grant_type': 'password',
                    'username': OAuth2Client.username,
                    'password': OAuth2Client.password,
                    'scope': OAuth2Client.scope
                };
                return $.ajax({
                    type: 'POST',
                    url: OAuth2Client.token_uri,
                    headers: {'Authorization': 'Basic ' + clientToken}, // Authorization Basic
                    crossDomain: true,
                    dataType: 'json',
                    data: paramsData
                })
            }

            // Store token
            function storeToken(data) {
                OAuth2Token.access_token = data.access_token;
                OAuth2Token.refresh_token = data.refresh_token;
                OAuth2Token.expires_in = data.expires_in
            }

            // Info token
            function infoToken(data) {
                if (debug) {
                    OAuth2Token.expires_in = new Date((new Date()).getTime() + Number(data.expires_in) / 60 * 60000);
                    console.log(" access_token: "+data.access_token+" ("+OAuth2Token.expires_in.getHours()+"h"+OAuth2Token.expires_in.getMinutes()+")");
                    console.log("refresh_token: "+data.refresh_token);
                    $(form_auth+" #access_token").html(OAuth2Token.access_token + " (" + OAuth2Token.expires_in.getHours() + "h" + OAuth2Token.expires_in.getMinutes() + ")").css("color", "green");
                    $(form_auth+" #refresh_token").html(OAuth2Token.refresh_token)
                }
            }

            // Reset token
            function cleanToken() {
                OAuth2Token = { 'access_token': '', 'refresh_token': '', 'expires_in': new Date() }
            }

            // Refresh token
            function refreshToken(){
                var clientToken = btoa(OAuth2Client.client+":"+OAuth2Client.secret);
                var paramsData = {
                    'grant_type': 'refresh_token',
                    'refresh_token': OAuth2Token.refresh_token
                };
                return $.ajax({
                    type: 'POST',
                    url: OAuth2Client.token_uri,
                    headers: {'Authorization': 'Basic ' + clientToken}, // Authorization Basic
                    crossDomain: true,
                    dataType: 'json',
                    data: paramsData
                })
            }
        }(jQuery));
    </script>

    <!-- Get token curl -s acme:acmesecret@localhost:9191/uaa/oauth/token -d grant_type=password -d client_id=acme -d scope=read -d username=franck -d password=spring -->
    <!-- Get refresh Token curl -s acme:acmesecret@localhost:9191/uaa/oauth/token -d grant_type=refresh_token -d refresh_token=d45d8568-9e20-40ed-a7dc-2c2cbcb98e07 -->
    <!-- Get list tclouds curl http://localhost:9999/tclouds/list?access_token=2bb260c1-aed0-4ba0-abe9-b7ba928355af -->
    <!-- Page service tclouds curl curl http://localhost:9999/tcloud-service/tclouds/names?access_token=2bb260c1-aed0-4ba0-abe9-b7ba928355af -->

    <!--
    -- JWT (Jason Web Token) see online openid content on https://jwt.io/
    -- jti field prevent the JWT from being replayed!
    {access_token:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzk1NTMwNjEsInVzZXJfbmFtZSI6ImZyYW5jayIsImF1dGhvcml0aWVzIjpbIlJPTEVfQURNSU4iLCJST0xFX1VTRVIiXSwianRpIjoiMDMzZjhkNGItZjIwMC00MTdhLWIxNDItNmYwZDAwNmQ2NDU2IiwiY2xpZW50X2lkIjoic3VwZXJtZSIsInNjb3BlIjpbIm9wZW5pZC5yZWFkIl19.uyfPq7aFr8rza2AeMvN6gbJkLeSfmpHwhGGuFO6InGfJ6S2u0M_-96BKW2gTSPbNu_3vJ9oFotcZZmiTez0lFnR2CEi2mHQF-maMl7HBlWGf1qrXCd_Lx9oNXwhGnXrKcqicNnc2_jR4bGMDjKeS1ywessdSL_vVqkzMDwqIUFE"
    expires_in:1799
    jti:"033f8d4b-f200-417a-b142-6f0d006d6456"
    refresh_token:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJmcmFuY2siLCJzY29wZSI6WyJvcGVuaWQucmVhZCJdLCJhdGkiOiIwMzNmOGQ0Yi1mMjAwLTQxN2EtYjE0Mi02ZjBkMDA2ZDY0NTYiLCJleHAiOjE0Nzk1NTQ4NjEsImF1dGhvcml0aWVzIjpbIlJPTEVfQURNSU4iLCJST0xFX1VTRVIiXSwianRpIjoiODQwNzc3NmYtNjQ2My00OGUwLWFiZjMtMDQ5Zjc0MzA5Nzk4IiwiY2xpZW50X2lkIjoic3VwZXJtZSJ9.uGFt2rHzd2k8_fM8T8fg-sf1pYOU4ATeHEAjzp0E_VfpqIdkLqrEkIA6Sl1b-pfZWJt-S5pN0FoKEcgCpg1XX7pwSS43gXwMROEc43cYLxrrKRPGGvZH0LhaxdAiUu8kIG0KoJpQHJrM-wGoNmWFI1_BPQ8WOcivTVYCCJy793k"
    scope:"openid.read"
    token_type:"bearer"}
    -->

    <script type="text/javascript">

    var jSSO = new JSSOAuth2({reloadSSOServices: reloadSSOServices, loginSSOError: loginSSOError, debug: true});

    $(function () {

        // Events UI interactions
        $('#login').click(function() {
            cleanUI();
            jSSO.SSOLogin();
            showUI()
        });

        $('#logout').click(function() {
            cleanUI();
            jSSO.SSOCleanToken()
        });

        $('#refresh').click(function() {
            jSSO.SSOToken().refresh_token == '' ? jSSO.SSOLogin() : jSSO.SSORefresh()
        });

        $('#service').click(function() {
            jSSO.SSOToken().access_token == '' ? jSSO.SSOLogin() : ajaxService()
        });

        $('#serviceList').click(function() {
            jSSO.SSOToken().access_token == '' ? jSSO.SSOLogin() : ajaxListService()
        });

        // first call login!
        //jSSO.SSOLogin()
    });

    // User Interface utils
    function cleanUI() {
        $("#access_token").empty().css("color", "black");
        $("#refresh_token").empty().css("color", "black");
        emptyUI()
    }
    function emptyUI() {
        $("#results").empty();
        $("#resultsList").empty();
        $("#error").empty()
    }
    function showUI() {
        $("#refresh").show();
        $("#service").show();
        $("#serviceList").show();
        $("#logout").show()
    }


    /**
     * Reload/load all resources protected by OAuth2!
     * All asynchronous ajax services!
     */
    function reloadSSOServices() {
        ajaxService();
        ajaxListService()
    }

    function loginSSOError(xhr) {
        var jsonResp = JSON.parse(xhr.responseText);
        $("#error").html(xhr.status+" "+jsonResp.error+" "
                +(jsonResp.error_description == undefined) ? jsonResp.message : jsonResp.error_description).css("color","red");
    }

    // Ajax Client Services, attach deferred.promise(jqXHR)
    function ajaxService() {
        var ajax = tcloudService().done(resultService).fail(errorServices);
        $.when(ajax).fail(function() {
            // http status 401 Unauthorized
            if (ajax.status == 401) jSSO.SSORefresh()
        })
    }

    function ajaxListService() {
        var ajax = tcloudListService().done(resultListService).fail(errorServices);
        $.when(ajax).fail(function() {
            // http status 401 Unauthorized
            if (ajax.status == 401) jSSO.SSORefresh()
        })
    }

    // Handle ajax error services
    function errorServices(xhr) {
        //$("#error").html(xhr.status+" "+xhr.responseText).css("color","red");
        console.log(xhr.status + " " + xhr.responseText)
    }

    /**
     * Service tcloud names with uri: http://localhost:9999/tclouds/names (or simple html page!)
     */
    function tcloudService(){
        return $.ajax({
            type: 'GET',
            url: 'http://localhost:9999/tclouds-service/names',
            crossDomain: true,
            headers: {'Authorization': 'Bearer '+ jSSO.SSOToken().access_token}, // Authorization Bearer!
            dataType: 'html'
        })
    }
    function resultService (data) {
        $("#results").html(data)
    }

    /**
     * Service tclouds list with uri: http://localhost:9999/tclouds/list (or simple json list!)
     */
    function tcloudListService(){
        return $.ajax({
            type: 'GET',
            url: 'http://localhost:9999/tclouds/list',
            crossDomain: true,
            headers: {'Authorization': 'Bearer '+ jSSO.SSOToken().access_token}, // Authorization Bearer!
            dataType: 'json'
        })
    }
    function resultListService (data) {
        var layer = $("#resultsList").empty().append("Tclouds-service :").append("<br>");
        $.each(data, function(i, el) {
            layer.append($('<span>', { id: 'tcloud_'+el.id, text: el.id+' - '+el.tcloudName})
                    .addClass((i % 2 == 0)?"even":"odd"))
                    .append('<br>')
        })
    }
    </script>
</head>

<body>

<div>
    <form id="form_auth">
        <div>
            <div><input name="username" placeholder="Username" value="franck"/></div>
            <div><input type="password" name="password" placeholder="Password" value="spring"/></div>
            <div>
                <input type="button" id="login" name="login" value="login"/>
                <input type="button" id="refresh" name="refresh" value="Refresh Token" style="display: none;"/>
                <input type="button" id="logout" name="logout" value="logout" style="display: none;"/><br/>
                <input type="button" id="service" name="tcloud" value="Tcloud Service" style="display: none;"/>
                <input type="button" id="serviceList" name="tclouds" value="Tcloud ListService" style="display: none;"/><br/>
                OAuth2 token : <span id="access_token"></span><br/>
                OAuth2 refresh token : <span id="refresh_token"></span><br/>
                <div>
                    <div id="results" class="results"></div>
                    <div id="resultsList" class="results"></div>
                </div>
                <span id="error"></span>
            </div>
        </div>
    </form>
</div>

</body>
</html>