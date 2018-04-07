package org.sonarqube.auth.bitbucket;

/**
 * Simple DTO containing all necessary auth data
 *
 * @author Artem_Vozhdayenko
 */
public class OAuthCredentials {
  private final String userName;
  private final String displayName;
  private final String email;

  public OAuthCredentials(String userName, String displayName, String email) {
    this.userName = userName;
    this.displayName = displayName;
    this.email = email;
  }

  public String getUserName() {
    return userName;
  }

  public String getDisplayName() {
    return displayName;
  }

  public String getEmail() {
    return email;
  }
}
