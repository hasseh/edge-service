package com.polarbookshop.edgeservice.user;

import com.polarbookshop.edgeservice.config.SecurityConfig;
import com.polarbookshop.edgeservice.user.User;
import com.polarbookshop.edgeservice.user.UserController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@WebFluxTest(UserController.class)
@Import(SecurityConfig.class)
public class UserControllerTests {
  @Autowired
  WebTestClient webClient;
  @MockBean
  ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;

  @Test
  void whenNotAuthenticatedThen401() {
    webClient
        .get()
        .uri("/user")
        .exchange()
        .expectStatus().isUnauthorized();
  }

  @Test
  void whenAuthenticatedThenReturnUser() {
    var expectedUser = new User("jon.snow", "Jon", "Snow", List.of("employee", "customer"));
    webClient
        .mutateWith(configureMockOidcLogin(expectedUser))
        .get()
        .uri("/user")
        .exchange()
        .expectStatus().is2xxSuccessful()
        .expectBody(User.class)
        .value(user -> assertThat(user).isEqualTo(expectedUser));
  }

  @Test
  void whenLogoutAuthenticatedAndWithCsrfTokenThen302() {
    when(reactiveClientRegistrationRepository.findByRegistrationId("test")).thenReturn(Mono.just(testClientRegistration()));
    webClient.mutateWith(SecurityMockServerConfigurers.mockOidcLogin())
        .mutateWith(SecurityMockServerConfigurers.csrf())
        .post()
        .uri("/logout")
        .exchange()
        .expectStatus().isFound();
  }

  private ClientRegistration testClientRegistration() {
    return ClientRegistration.withRegistrationId("test")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .clientId("test")
        .authorizationUri("https://sso.polarbookshop.com/auth")
        .tokenUri("https://sso.polarbookshop.com/token")
        .redirectUri("https://polarbookshop.com")
        .build();
  }

  private SecurityMockServerConfigurers.OidcLoginMutator configureMockOidcLogin(User expectedUser) {
    return SecurityMockServerConfigurers.mockOidcLogin().idToken(builder -> {
      builder.claim(StandardClaimNames.PREFERRED_USERNAME, expectedUser.username());
      builder.claim(StandardClaimNames.GIVEN_NAME, expectedUser.firstName());
      builder.claim(StandardClaimNames.FAMILY_NAME, expectedUser.lastName());
    });
  }
}
