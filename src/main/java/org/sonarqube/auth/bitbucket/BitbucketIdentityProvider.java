/*
 * Bitbucket Authentication for SonarQube
 * Copyright (C) 2016-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonarqube.auth.bitbucket;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Token;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.model.Verifier;
import com.github.scribejava.core.oauth.OAuthService;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.sonar.api.server.ServerSide;
import org.sonar.api.server.authentication.Display;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;
import org.sonar.api.server.authentication.UserIdentity;

import javax.servlet.http.HttpServletRequest;

@ServerSide
public class BitbucketIdentityProvider implements OAuth2IdentityProvider {

  public static final String REQUIRED_SCOPE = "account";
  public static final String KEY = "bitbucket";

  private final BitbucketSettings settings;
  private final UserIdentityFactory userIdentityFactory;
  private final BitbucketScribeApi10a scribeApi10a;

  public BitbucketIdentityProvider(
    BitbucketSettings settings,
    UserIdentityFactory userIdentityFactory,
    BitbucketScribeApi10a scribeApi10a) {
    this.settings = settings;
    this.userIdentityFactory = userIdentityFactory;
    this.scribeApi10a = scribeApi10a;
  }

  @Override
  public String getKey() {
    return KEY;
  }

  @Override
  public String getName() {
    return "Bitbucket";
  }

  @Override
  public Display getDisplay() {
    return Display.builder()
      // URL of src/main/resources/static/bitbucket.svg at runtime
      .setIconPath("/static/authbitbucket/bitbucket.svg")
      .setBackgroundColor("#205081")
      .build();
  }

  @Override
  public boolean isEnabled() {
    return settings.isEnabled();
  }

  @Override
  public boolean allowsUsersToSignUp() {
    return settings.allowUsersToSignUp();
  }

  @Override
  public void init(InitContext context) {
    OAuthService scribe = newScribeBuilder(context).scope(REQUIRED_SCOPE).build();
    Token requestToken = scribe.getRequestToken();
    String url = scribe.getAuthorizationUrl(requestToken);
    context.redirectTo(url);
  }

  @Override
  public void callback(CallbackContext context) {
    HttpServletRequest request = context.getRequest();
    OAuthService scribe = newScribeBuilder(context).scope(REQUIRED_SCOPE).build();
    Token accessToken =
      scribe.getAccessToken(
        new Token(request.getParameter("oauth_token"), scribe.getConfig().getApiSecret()),
        new Verifier(request.getParameter("oauth_verifier")));

    String userName = fetchUserName(scribe, accessToken);
    OAuthCredentials credentials = fetchUserDetails(scribe, accessToken, userName);

    UserIdentity userIdentity = userIdentityFactory.create(credentials);
    context.authenticate(userIdentity);
    context.redirectToRequestedPage();
  }

  private String fetchUserName(OAuthService scribe, Token accessToken) {
    OAuthRequest userRequest =
      new OAuthRequest(Verb.GET, settings.webURL() + "plugins/servlet/applinks/whoami", scribe);
    scribe.signRequest(accessToken, userRequest);
    Response userResponse = userRequest.send();
    if (!userResponse.isSuccessful()) {
      throw new IllegalStateException("Can not get Bitbucket user profile." + userResponse);
    }

    // Username is a body of the response in fact
    return userResponse.getBody();
  }

  private OAuthCredentials fetchUserDetails(
    OAuthService scribe, Token accessToken, String userName) {
    OAuthRequest userDetailsRequest =
      new OAuthRequest(Verb.GET, settings.webURL() + "rest/api/latest/users/" + userName, scribe);
    scribe.signRequest(accessToken, userDetailsRequest);
    Response detailsResponse = userDetailsRequest.send();
    if (!detailsResponse.isSuccessful()) {
      throw new IllegalStateException("Can't get user details." + detailsResponse);
    }

    JsonObject asJsonObject = new JsonParser().parse(detailsResponse.getBody()).getAsJsonObject();
    String emailAddress = asJsonObject.get("emailAddress").getAsString();
    String displayName = asJsonObject.get("displayName").getAsString();
    return new OAuthCredentials(userName, displayName, emailAddress);
  }

  private ServiceBuilder newScribeBuilder(OAuth2IdentityProvider.OAuth2Context context) {
    if (!isEnabled()) {
      throw new IllegalStateException("Bitbucket authentication is disabled");
    }
    return new ServiceBuilder()
      .provider(scribeApi10a)
      .apiKey(settings.clientId())
      .apiSecret(settings.clientSecret())
      .grantType("authorization_code")
      .callback(context.getCallbackUrl());
  }
}
