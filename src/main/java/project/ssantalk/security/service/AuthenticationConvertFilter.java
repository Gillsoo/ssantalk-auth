package project.ssantalk.security.service;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import project.ssantalk.application.SsantalkApplicationProperties;
import project.ssantalk.application.service.LoginProcessService;
import project.ssantalk.application.service.component.UserMasterAuthenticationCache;
import project.ssantalk.entity.repository.SessionMasterService;
import project.ssantalk.entity.struct.SessionMstrTM.LoginSessionTM;
import project.ssantalk.security.SecuritySpec.AuthenticateException;
import project.ssantalk.security.UserMasterAuthentication;
import tools.spring.CompositeApplicationContainer;

import javax.annotation.PostConstruct;
import javax.persistence.EntityNotFoundException;
import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;

/**
 * @author dragon
 * @since 2021. 03. 14.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationConvertFilter {
    final SsantalkApplicationProperties applicationProperties;

    final LoginProcessService loginProcessService;

    final SessionMasterService sessionMasterService;

    final CompositeApplicationContainer container;

    final UserMasterAuthenticationCache cache;

    private long sessionTimeoutMilli = -1L; // default 1 hour

    private long sessionRefreshMilli = -1L; // default 1 minute

    @PostConstruct
    private void onPostConstruct() {
        sessionTimeoutMilli = applicationProperties.getAuthorization()
                .getSessionTimeoutMilli();
        sessionRefreshMilli = applicationProperties.getAuthorization()
                .getSessionRefreshMilli();
    }

    @Getter
    final Filter filter = (request,
                           response,
                           chain) -> {
        AuthenticationConvertFilter.this.convert((HttpServletRequest) request);

        chain.doFilter(request,
                response);
    };

    @Transactional
    public void convert(HttpServletRequest request) {
        final String tokenCandidate = request.getHeader("Authorization");

        if (StringUtils.isEmpty(tokenCandidate) || !tokenCandidate.startsWith("Bearer")) {
            return;
        }

        final String token = tokenCandidate.substring(7)
                .trim();

        try {
            UserMasterAuthentication authentication = cache.get(token,
                    () -> {
                        try {
                            final LoginSessionTM tm = this.sessionMasterService.getSession(token);

                            return new UserMasterAuthentication(tm);
                        } catch (EntityNotFoundException exception) {
                            if (log.isDebugEnabled()) {
                                log.debug(String.format("[%s] is invalid state!",
                                        token));
                            }
                            return null;
                        }
                    });

            if (null != authentication && log.isDebugEnabled()) {
                log.debug(authentication.toString());
            }
            // TODO : check session expire & update

            return;
        } catch (AuthenticateException authenticateException) {
            switch (authenticateException.getExceptionType()) {
                case AUTHENTICATE_TOKEN_NOT_FOUND: {
                    return;
                }
            }
            throw authenticateException;
        }
    }

    public UserMasterAuthentication getTokenInfo(String token) {
        try {
            UserMasterAuthentication authentication = cache.get(token,
                    () -> {
                        try {
                            final LoginSessionTM tm = this.sessionMasterService.getSession(token);

                            return new UserMasterAuthentication(tm);
                        } catch (EntityNotFoundException exception) {
                            if (log.isDebugEnabled()) {
                                log.debug(String.format("[%s] is invalid state!",
                                        token));
                            }
                            return null;
                        }
                    });

            if (null != authentication && log.isDebugEnabled()) {
                log.debug(authentication.toString());
            }
            // TODO : check session expire & update

            return authentication;
        } catch (AuthenticateException authenticateException) {
            switch (authenticateException.getExceptionType()) {
                case AUTHENTICATE_TOKEN_NOT_FOUND: {
                    return null;
                }
            }
            throw authenticateException;
        }
    }
}
