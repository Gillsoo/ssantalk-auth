package project.ssantalk.security.component;

import lombok.Getter;

import java.util.concurrent.TimeUnit;

/**
 * @author dragon
 * @since 2021. 03. 14.
 */
public class AuthenticationProperties {
	@Getter
	private long sessionTimeout = 36000L; // default 1 hour

	@Getter
	private long sessionRefresh = 600L; // default 1 minute

	@Getter
	private long sessionTimeoutMilli = -1L; // default 1 hour

	@Getter
	private long sessionRefreshMilli = -1L; // default 1 minute

	public void setSessionTimeout(long sessionTimeout) {
		this.sessionTimeout = sessionTimeout;
		this.sessionTimeoutMilli = TimeUnit.SECONDS.toMillis(sessionTimeout);
	}

	public void setSessionRefresh(long sessionRefresh) {
		this.sessionRefresh = sessionRefresh;
		this.sessionRefreshMilli = TimeUnit.SECONDS.toMillis(sessionRefresh);
	}

	public void setSessionRefreshMilli(long sessionRefreshMilli) {
		this.sessionRefreshMilli = sessionRefreshMilli;
		this.sessionRefresh = TimeUnit.MILLISECONDS.toSeconds(sessionRefreshMilli);
	}

	public void setSessionTimeoutMilli(long sessionTimeoutMilli) {
		this.sessionTimeoutMilli = sessionTimeoutMilli;
		this.sessionTimeout = TimeUnit.MILLISECONDS.toSeconds(sessionTimeoutMilli);
	}
}
