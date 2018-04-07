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

import javax.annotation.Nullable;

import org.sonar.api.server.ServerSide;
import org.sonar.api.server.authentication.UserIdentity;

import static java.lang.String.format;
import static org.sonarqube.auth.bitbucket.BitbucketSettings.LOGIN_STRATEGY_UNIQUE;

/**
 * Converts Bitbucket JSON responses to {@link UserIdentity}
 */
@ServerSide
public class UserIdentityFactory {

  private final BitbucketSettings settings;

  public UserIdentityFactory(BitbucketSettings settings) {
    this.settings = settings;
  }

  public UserIdentity create(OAuthCredentials credentials) {
    UserIdentity.Builder builder = builder(credentials);
    builder.setEmail(credentials.getEmail());
    return builder.build();
  }

  private UserIdentity.Builder builder(OAuthCredentials credentials) {
    return UserIdentity.builder()
      .setProviderLogin(credentials.getUserName())
      .setLogin(generateLogin(credentials))
      .setName(generateName(credentials));
  }

  private String generateLogin(OAuthCredentials credentials) {
    switch (settings.loginStrategy()) {
      case BitbucketSettings.LOGIN_STRATEGY_PROVIDER_LOGIN:
        return credentials.getUserName();
      case LOGIN_STRATEGY_UNIQUE:
        return generateUniqueLogin(credentials);
      default:
        throw new IllegalStateException(
          format("Login strategy not supported : %s", settings.loginStrategy()));
    }
  }

  private static String generateName(OAuthCredentials credentials) {
    String name = credentials.getDisplayName();
    return name == null || name.isEmpty() ? credentials.getUserName() : name;
  }

  private static String generateUniqueLogin(OAuthCredentials credentials) {
    return format("%s@%s", credentials.getUserName(), BitbucketIdentityProvider.KEY);
  }
}
