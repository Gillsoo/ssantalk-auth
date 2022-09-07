package project.ssantalk.resources;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;
import project.ssantalk.application.SsantalkApplicationProperties;
import project.ssantalk.application.service.LoginProcessService;
import project.ssantalk.entity.repository.BankInfoService;
import project.ssantalk.entity.struct.AnonymousTM.GeneralMessageTM;
import project.ssantalk.entity.struct.AnonymousTM.UserLoginRequest;
import project.ssantalk.entity.struct.SessionMstrTM.LoginSessionTM;
import project.ssantalk.security.SecuritySpec;
import project.ssantalk.security.UserMasterAuthentication;
import project.ssantalk.security.service.AuthenticationConvertFilter;
import project.ssantalk.utils.SsantalkUtil;

import javax.servlet.http.HttpServletRequest;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(path = "/auth")
public class AuthenticateResource {
    final LoginProcessService loginProcessService;

    final BankInfoService bankInfoService;

    final SsantalkApplicationProperties properties;

    final AuthenticationConvertFilter convertFilter;

    @PostMapping(path = "/login")
    public LoginSessionTM authenticate(HttpServletRequest request,
                                       @RequestBody UserLoginRequest loginVM) {
        // set additional infos
        loginVM.setUserAgent(request.getHeader("User-Agent"));
//		loginVM.setRemoteAddress(request.getRemoteAddr());
        String remoteAddress = SsantalkUtil.getClientIp(request);
        loginVM.setRemoteAddress(remoteAddress);

        try {
            return loginProcessService.login(loginVM);
        } catch (Throwable thw) {
            if (log.isDebugEnabled()) {
                log.error("login error",
                        thw);
            } else {
                log.error(String.format("login error [%s]",
                        thw.getMessage()));
            }
            return LoginSessionTM.builder()
                    .failCount(1)
                    .success(false)
                    .code(SecuritySpec.AuthenticateExceptionType.AUTHENTICATE_USER_NOT_FOUND.getResponseCode())
                    .message(SecuritySpec.AuthenticateExceptionType.AUTHENTICATE_USER_NOT_FOUND.getResponseMessage())
                    .build();
        }
    }


    @GetMapping(path = "/logout")
    @Secured({
            "ROLE_admin",
            "ROLE_user",
            "ROLE_partner"
    })
    public GeneralMessageTM logout() {
        try {
            return loginProcessService.logout();
        } catch (Throwable thw) {
            if (log.isDebugEnabled()) {
                log.error("logout error",
                        thw);
            } else {
                log.error(String.format("logout error [%s]",
                        thw.getMessage()));
            }
            return GeneralMessageTM.builder()
                    .error(true)
                    .message(thw.getMessage())
                    .build();
        }
    }


    @GetMapping(path = "/token")
    public ResponseEntity<LoginSessionTM> authenticateToken(HttpServletRequest request, @RequestParam("Authorization") String param, @RequestParam("key") String key) {
        UserMasterAuthentication auth = convertFilter.getTokenInfo(param);
        return new ResponseEntity<>(auth.getTm(), HttpStatus.OK);
    }

}
