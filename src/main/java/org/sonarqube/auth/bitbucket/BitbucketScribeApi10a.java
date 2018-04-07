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

import com.github.scribejava.core.builder.api.DefaultApi10a;
import com.github.scribejava.core.extractors.AccessTokenExtractor;
import com.github.scribejava.core.model.Token;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.services.RSASha1SignatureService;
import com.github.scribejava.core.services.SignatureService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.sonar.api.server.ServerSide;

@ServerSide
public class BitbucketScribeApi10a extends DefaultApi10a {

  private static final String OAUTH1a_BASE = "plugins/servlet/oauth/";

  private final BitbucketSettings settings;

  public BitbucketScribeApi10a(BitbucketSettings settings) {
    this.settings = settings;
  }

  @Override
  public String getAccessTokenEndpoint() {
    return settings.webURL() + OAUTH1a_BASE + "access-token";
  }

  @Override
  public Verb getAccessTokenVerb() {
    return Verb.POST;
  }

  @Override
  public String getAuthorizationUrl(Token token) {
    return settings.webURL() + OAUTH1a_BASE + "authorize?oauth_token=" + token.getToken();
  }

  @Override
  public String getRequestTokenEndpoint() {
    return settings.webURL() + OAUTH1a_BASE + "request-token";
  }

  @Override
  public SignatureService getSignatureService() {
    return new RSASha1SignatureService(getSignatureSecretKey());
  }

  private PrivateKey getSignatureSecretKey() {
    PKCS8EncodedKeySpec keySpec =
      new PKCS8EncodedKeySpec(
        Base64.getDecoder()
          .decode(
            settings
              .signKey()
              .replace("-----BEGIN PRIVATE KEY-----", "")
              .replace("-----END PRIVATE KEY-----", "")
              .replaceAll("\\s+", "")));
    try {
      return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new IllegalStateException("Invalid secret key for signature", e);
    }
  }

  @Override
  public AccessTokenExtractor getAccessTokenExtractor() {
    return s -> {
      Map<String, String> vars = stringToMap(s);

      String token = vars.get("oauth_token");
      String secret = vars.get("oauth_token_secret");

      return new Token(token, secret);
    };
  }

  private static Map<String, String> stringToMap(String input) {
    Map<String, String> map = new HashMap<>();

    String[] nameValuePairs = input.split("&");
    for (String nameValuePair : nameValuePairs) {
      String[] nameValue = nameValuePair.split("=");
      map.put(nameValue[0], nameValue.length > 1 ? nameValue[1] : "");
    }

    return map;
  }
}
