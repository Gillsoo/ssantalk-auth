package project.ssantalk.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.List;

/**
 * @author dragon
 * @since 2021. 06. 01.
 */
public interface SecuritySpec {
	class AuthenticateException
								extends
									RuntimeException {
		@Getter
		final AuthenticateExceptionType exceptionType;

		@Getter
		final Object handbag;

		public AuthenticateException(	AuthenticateExceptionType exceptionType,
										String message,
										Object handbag,
										Throwable cause) {
			super(	message,
					cause);
			this.exceptionType = exceptionType;
			this.handbag = handbag;
		}
	}

	enum SecurityUserType {
		user,
		admin,
		partner;

		@Getter
		final String type;

		@Getter
		final List<SimpleGrantedAuthority> authorities;

		@Getter
		final List<String> roles;

		SecurityUserType() {
			this.type = name();
			this.authorities = Arrays.asList(new SimpleGrantedAuthority("ROLE_".concat(this.type)));
			this.roles = Arrays.asList(this.type);
		}
	}

	@RequiredArgsConstructor
	enum AuthenticateExceptionType {
		AUTHENTICATE_INVALID_AUTH_SCOPE("401", "user not found"),
		AUTHENTICATE_PASSWORD_DIFFERENT("401", "password does not match"),
		AUTHENTICATE_TOKEN_NOT_FOUND("403", "token not found"),
		AUTHENTICATE_USER_NOT_FOUND("402", "user not found"),
		AUTHENTICATE_LOCKED_ACCOUNT("410", "account is locked"),
		AUTHENTICATE_BLOCKED_ACCOUNT("412", "account is Blocked"),
		AUTHENTICATE_SLEEP_ACCOUNT("413", "account is sleep"),
		AUTHENTICATE_WITHDRAW_ACCOUNT("411", "account is withdrawal");

		@Getter
		final String responseCode;

		@Getter
		final String responseMessage;

		public final AuthenticateException generate() {
			return generate(responseMessage);
		}

		public final AuthenticateException generate(String message) {
			return generate(message,
							null,
							null);
		}

		public final AuthenticateException generate(String message,
													Throwable cause) {
			return generate(message,
							null,
							cause);
		}

		public final AuthenticateException generate(String message,
													Object handbag,
													Throwable cause) {
			return new AuthenticateException(	this,
												message,
												handbag,
												cause);
		}
	}

}
