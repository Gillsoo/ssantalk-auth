package project.ssantalk.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import project.ssantalk.application.SsantalkApplicationProperties;
import project.ssantalk.application.service.component.PasswordEncoderImpl;
import project.ssantalk.application.service.component.UserMasterAuthenticationCache;
import project.ssantalk.entity.exception.SsantalkRuntimeException;
import project.ssantalk.entity.model.*;
import project.ssantalk.entity.model.EntityModelProviders.UserProvider;
import project.ssantalk.entity.repository.*;
import project.ssantalk.entity.struct.AnonymousTM.GeneralMessageTM;
import project.ssantalk.entity.struct.AnonymousTM.UserLoginRequest;
import project.ssantalk.entity.struct.ApiResponseGenerator;
import project.ssantalk.entity.struct.ApiResponseResultType;
import project.ssantalk.entity.struct.EnumTypes;
import project.ssantalk.entity.struct.EnumTypes.LoginType;
import project.ssantalk.entity.struct.SessionMstrTM.LoginSessionTM;
import project.ssantalk.entity.struct.UserMasterTM.*;
import project.ssantalk.entity.util.SsantalkEntityUtil;
import project.ssantalk.security.SecuritySpec.AuthenticateExceptionType;
import project.ssantalk.security.UserMasterAuthentication;
import tools.component.BeanModelTypeMapper;
import tools.orm.jpa.JpaAssist;
import tools.orm.jpa.JpaAssistSpec.JpaAssistAware;
import tools.spring.CompositeApplicationContainer;

import javax.transaction.Transactional;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * @author dragon
 * @since 2021. 03. 14.
 */
@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class LoginProcessService
        implements
        JpaAssistAware {
    final CompositeApplicationContainer container;

    final SessionMasterService sessionMasterService;

    final UserMasterService userMasterService;

    final AdminMstrService adminMstrService;

    final PasswordEncoderImpl encoder;

    final UserMasterAuthenticationCache cache;

    final UserCallerNumberService userCallerNumberService;

    final UserMasterSleepRepository userMasterSleepRepository;

    final PartnerMstrService partnerMstrService;

    final SsantalkApplicationProperties properties;

    SimpleDateFormat dashDateFormat = new SimpleDateFormat("yyyy-MM-dd");

    JpaAssist assist = null;

    BeanModelTypeMapper typeMapper = null;

    @Override
    public int getOrder() {
        return Integer.MAX_VALUE;
    }

    @Override
    public void aware(JpaAssist assist) {
        this.assist = assist;
        this.typeMapper = container.getBean(BeanModelTypeMapper.class);

    }

    /**
     * 사용자에 의해 직접 패스워드를 수정
     *
     * @param request
     * @return
     */
    public UserMstrChangePasswordResponse changePassword(String userId,
                                                         UserMstrChangePasswordRequest request) {
//        final UserMstr master = this.getUserMstrUsePassword(userId,
//                request.getOldPassword());
//
//        master.setLoginPswd(encoder.encode(request.getNewPassword()));
//
//        userMasterService.update(master);
//
//        return UserMstrChangePasswordResponse.builder()
//                .success(true)
//                .message("complete")
//                .build();
        UserMstr master = userMasterService.findLoginId(userId);
        //사용자 없음
        if (master == null) {
            throw new IllegalArgumentException(String.format("[%s] is not matched",
                    userId));
        }
        //계정 잠금상태인지 확인
        if (StringUtils.equalsIgnoreCase(master.getUserLock(), "Y")) {
            return UserMstrChangePasswordResponse.builder()
                    .success(false)
                    .code(AuthenticateExceptionType.AUTHENTICATE_LOCKED_ACCOUNT.getResponseCode())
                    .message(AuthenticateExceptionType.AUTHENTICATE_LOCKED_ACCOUNT.getResponseMessage())
                    .failCnt(master.getFailCnt())
                    .build();
        }
        //기존 비밀번호 불일치
        if (!encoder.matches(request.getOldPassword(), master.getLoginPswd())) {
            master.setFailCnt(master.getFailCnt() + 1);
            //5회 이상 불일치시 계정 잠금.
            if (master.getFailCnt() >= 5) {
                master.setUserLock("Y");
            }
            return UserMstrChangePasswordResponse.builder()
                    .success(false)
                    .code(AuthenticateExceptionType.AUTHENTICATE_PASSWORD_DIFFERENT.getResponseCode())
                    .message(AuthenticateExceptionType.AUTHENTICATE_PASSWORD_DIFFERENT.getResponseMessage())
                    .failCnt(master.getFailCnt())
                    .build();
        }
        master.setLoginPswd(encoder.encode(request.getNewPassword()));
        master.setMngrDate(new Date());
        master.setFailCnt(0);
        master.setUserLock("N");
        return UserMstrChangePasswordResponse.builder()
                .message("Success")
                .code("0")
                .failCnt(0)
                .build();
    }

    public final UserMstr getUserMstrUsePassword(Long userId,
                                                 String password) {
        UserMstr master = userMasterService.getOne(userId);

        if (!encoder.isEncoded(master.getLoginPswd())) {
            master.setLoginPswd(encoder.encode(master.getLoginPswd()));
            userMasterService.update(master);
        }

        if (!encoder.matches(password,
                master.getLoginPswd())) {
            throw AuthenticateExceptionType.AUTHENTICATE_PASSWORD_DIFFERENT.generate();
        }
        return master;
    }

    public LoginSessionTM login(UserLoginRequest request) {
        switch (request.getLoginType()) {
            case "user": {
                return openUserSession(request);
            }

            case "admin": {
                return openAdminSession(request);
            }

            case "partner": {
                return openPartnerSession(request);
            }

            default: {
                break;
            }
        }

        throw new IllegalArgumentException(String.format("[%s] in invalid login type",
                request.getLoginType()));
    }

    /**
     * 비밀번호 매치 여부를 검사하고 encoding 되지 않은 password 는 encoding 하여 업데이트 함.
     *
     * @param provider  user info provider
     * @param loginType login type
     * @param request   login request
     */
    private LoginSessionTM createSessionOf(UserProvider provider,
                                           LoginType loginType,
                                           UserLoginRequest request) {
        if (!encoder.isEncoded(provider.getLoginPswd())) {
            provider.setLoginPswd(encoder.encode(provider.getLoginPswd()));
        }

        if (!encoder.matches(request.getPwd(),
                provider.getLoginPswd())) {
            Integer cnt = provider.getFailCnt();

            provider.setFailCnt(cnt == null ? 1
                    : cnt.intValue() + 1);

//			throw .AUTHENTICATE_PASSWORD_DIFFERENT.generate();

            log.error("password not matched : id : " + request.getId() + ", pw : " + request.getPwd());

            return LoginSessionTM.builder()
                    .failCount(provider.getFailCnt())
                    .success(false)
                    .code(AuthenticateExceptionType.AUTHENTICATE_PASSWORD_DIFFERENT.getResponseCode())
                    .message(AuthenticateExceptionType.AUTHENTICATE_PASSWORD_DIFFERENT.getResponseMessage())
                    .build();
        }

        if (provider.getFailCnt() >= 5) {
            log.error("password is locked : id : " + request.getId());
            return LoginSessionTM.builder()
                    .failCount(provider.getFailCnt())
                    .success(false)
                    .code(AuthenticateExceptionType.AUTHENTICATE_LOCKED_ACCOUNT.getResponseCode())
                    .message(AuthenticateExceptionType.AUTHENTICATE_LOCKED_ACCOUNT.getResponseMessage())
                    .build();
        }

        provider.setFailCnt(0);

        SessionMstr session = sessionMasterService.openSession(provider.getUserId(),
                loginType,
                request.getUserAgent(),
                request.getRemoteAddress());

        LoginSessionTM tm = LoginSessionTM.builder()
                .loginId(provider.getUserId())
                .loginName(provider.getLoginId())
                .loginType(session.getLoginType()
                        .name())
                .token(session.getToken())
                .build();
        // store session
        cache.set(session.getToken(),
                new UserMasterAuthentication(tm));

        return tm;
    }

    private LoginSessionTM openAdminSession(UserLoginRequest request) {
        AdminMstr master = adminMstrService.getByUserId(request.getId());

        try {
            return createSessionOf(master,
                    LoginType.admin,
                    request);
        } finally {
            adminMstrService.update(master);
        }
    }

    private LoginSessionTM openPartnerSession(UserLoginRequest request) {
        PartnerMstr master = partnerMstrService.getByUserId(request.getId());
        try {
            LoginSessionTM session = createSessionOf(master,
                    LoginType.partner,
                    request);
            session.setPartnerType(master.getAccountType().name());
            session.setPartnerStatus(master.getAccountStatus().name());


            switch (master.getAccountStatus()) {
                case JOIN_PROGRESS:
                    session.setSuccess(false);
                    session.setToken(null);
                    break;
                case WITHDRAWAL:
                    session.setCode(AuthenticateExceptionType.AUTHENTICATE_WITHDRAW_ACCOUNT.getResponseCode());
                    session.setMessage(AuthenticateExceptionType.AUTHENTICATE_WITHDRAW_ACCOUNT.getResponseMessage());
                    session.setSuccess(false);
                    session.setToken(null);
                    break;
                case LOCK:
                    session.setCode(AuthenticateExceptionType.AUTHENTICATE_LOCKED_ACCOUNT.getResponseCode());
                    session.setMessage(AuthenticateExceptionType.AUTHENTICATE_LOCKED_ACCOUNT.getResponseMessage());
                    session.setSuccess(false);
                    session.setToken(null);
                    break;
                case REJECT:
                    session.setSuccess(false);
                    session.setToken(null);
                    if (master.getFailCnt() >= 5) {
                        session.setCode(AuthenticateExceptionType.AUTHENTICATE_LOCKED_ACCOUNT.getResponseCode());
                        session.setMessage(AuthenticateExceptionType.AUTHENTICATE_LOCKED_ACCOUNT.getResponseMessage());
                    } else {
                        session.setPartnerMemo(master.getPartnerMemo());
                        try {
                            String reApplyCode = SsantalkEntityUtil.encodeAria(properties.getAria().getKey(), session.getLoginId().toString());
                            session.setPartnerReApplyCode(reApplyCode);
                        } catch (UnsupportedEncodingException | InvalidKeyException e) {
                            return new ApiResponseGenerator<LoginSessionTM>().fail(LoginSessionTM.builder().build(), ApiResponseResultType.ENCODED_ERROR);
                        }
                    }
                    break;
                default:
                    session.setPartnerCode(master.getPartnerCode());
                    break;
            }
            return session;
        } finally {
            partnerMstrService.update(master);
        }
    }

    private LoginSessionTM openUserSession(UserLoginRequest request) {
        UserMstr master = userMasterService.getByUserId(request.getId());

        if (master.getWithdraw()) {
            return LoginSessionTM.builder()
                    .failCount(null)
                    .success(false)
                    .code(AuthenticateExceptionType.AUTHENTICATE_WITHDRAW_ACCOUNT.getResponseCode())
                    .message(AuthenticateExceptionType.AUTHENTICATE_WITHDRAW_ACCOUNT.getResponseMessage())
                    .build();
        }

        if (master.getAccountStatus().equals(EnumTypes.UserAccountStatusType.BLOCK)) {
            return LoginSessionTM.builder()
                    .failCount(null)
                    .success(false)
                    .code(AuthenticateExceptionType.AUTHENTICATE_BLOCKED_ACCOUNT.getResponseCode())
                    .message(AuthenticateExceptionType.AUTHENTICATE_BLOCKED_ACCOUNT.getResponseMessage())
                    .build();
        }

        if (master.getAccountStatus().equals(EnumTypes.UserAccountStatusType.SLEEP)) {

            UserMstrSleep sleep = userMasterSleepRepository.findTopByUserIdOrderBySleepRgstDateDesc(master.getUserId());

            return LoginSessionTM.builder()
                    .failCount(null)
                    .success(false)
                    .code(AuthenticateExceptionType.AUTHENTICATE_SLEEP_ACCOUNT.getResponseCode())
                    .message(AuthenticateExceptionType.AUTHENTICATE_SLEEP_ACCOUNT.getResponseMessage())
                    .sleepDate(sleep.getSleepRgstDate())
                    .build();
        }

        try {
            return createSessionOf(master,
                    LoginType.user,
                    request);
        } finally {
            if (master.getFailCnt() >= 5) {
                master.setUserLock("Y");
            }
            userMasterService.update(master);
        }
    }

    public GeneralMessageTM logout() {
        final String token = Optional.ofNullable(SecurityContextHolder.getContext()
                        .getAuthentication())
                .filter(predicate -> predicate instanceof UserMasterAuthentication)
                .map(elm -> (UserMasterAuthentication) elm)
                .map(elm -> elm.getTm())
                .map(LoginSessionTM::getToken)
                .filter(predicate -> StringUtils.isNotEmpty(predicate))
                .orElseThrow(() -> new IllegalStateException(String.format("invalid authorize state [%s]",
                        SecurityContextHolder.getContext()
                                .getAuthentication())));

        // clear token
        sessionMasterService.closeSession(token);

        // clear cache
        cache.delete(token);

        return GeneralMessageTM.builder()
                .error(false)
                .message("success")
                .build();
    }

    public UserSignUpResponse userSignUp(UserSignUpRequest request) {
        Date now = new Date();
        Long partnerId = null;
        String partnerCode = null;
        if (!StringUtils.isEmpty(request.getRecommendCode())) {
            PartnerMstr partner = partnerMstrService.findByRecommendCode(request.getRecommendCode());
            if (partner != null) {
                switch (partner.getAccountStatus()) {
                    case NORMAL:
                    case JOIN_PROGRESS:
                    case LOCK:
                    case WITHDRAWAL_PROGRESS:
                        partnerId = partner.getUserId();
                        partnerCode = partner.getPartnerCode();
                        break;
                }
            }
        }
        UserMstr userMstr = UserMstr.builder()
                .loginId(request.getLoginId())
                .userName(request.getUserName())
                .phoneNumber(request.getPhoneNumber())
                .loginPswd(encoder.encode(request.getLoginPswd()))
                .corpId(Long.parseLong("0"))
                .remainSMS(0.0)
                .remainLMS(0.0)
                .remainMMS(0.0)
                .serviceTerm("Y")
                .privacyTerm("Y")
                .receiveEvent(StringUtils.equalsIgnoreCase(request.getReceiveEvent(), "Y") ? "Y" : "N")
                .keepAccountType(StringUtils.equalsIgnoreCase(request.getKeepAccountType(), "Y") ? "Y" : "N")
                .failCnt(0)
                .userLock("N")
                .userDi(request.getUserDi())
                .userPasswordUpdateDate(now)
                .callerCapacity(3)
                .accountStatus(EnumTypes.UserAccountStatusType.NORMAL)
                .receiveEventMngrDate(now)
                .rgstDate(now)
                .mngrDate(now)
                .partnerId(partnerId)
                .partnerCode(partnerCode)
                .build();

        userMstr = userMasterService.userSignUp(userMstr);

        DecimalFormat fm = new DecimalFormat("0000");

        //회원 가입과 동시에 가입된 번호로 발신번호 저장.
        UserCallerNumber userCaller = UserCallerNumber.builder()
                .userId(userMstr.getUserId())
                .callerName(userMstr.getUserName())
                .phoneNumber(request.getPhoneNumber())
                .masterFlag(true)
                .statusCode(fm.format(EnumTypes.PhoneNumberAuthenticateStatus.complete.ordinal()))
                .status(EnumTypes.PhoneNumberAuthenticateStatus.complete)
                .callerType("P")
                .thirdPartyReason(null)
                .rgstDate(new Date())
                .build();
        userCallerNumberService.callerSave(userCaller);


        return UserSignUpResponse.builder()
                .success(true)
                .message("complete")
                .loginId(userMstr.getLoginId())
                .userName(userMstr.getUserName())
                .build();
    }

    public UserIdCheckResponse checkId(String loginId) {

        UserMstr userMstr = userMasterService.checkId(loginId);

        return UserIdCheckResponse.builder()
                .loginId(loginId)
                .duplicateYn(userMstr == null ? "N" : "Y")
                .status(userMstr == null ? null : userMstr.getAccountStatus().name())
                .build();
    }

    public UserIdCheckResponse checkPartnerId(String loginId) {

        PartnerMstr partnerMstr = partnerMstrService.checkId(loginId);

        return UserIdCheckResponse.builder()
                .loginId(loginId)
                .duplicateYn(partnerMstr == null ? "N" : "Y")
                .status(partnerMstr == null ? null : partnerMstr.getAccountStatus().name())
                .build();
    }

    public FindUserDiResponse findUserDi(String userDi) {

        List<UserMstr> UserMstrList = userMasterService.findUserDi(userDi);
        List<UserIdResponse> userList = new ArrayList<>();
        if (UserMstrList.size() == 0) {
            return FindUserDiResponse.builder()
                    .success(false)
                    .userList(null)
                    .code(AuthenticateExceptionType.AUTHENTICATE_USER_NOT_FOUND.getResponseCode())
                    .message(AuthenticateExceptionType.AUTHENTICATE_USER_NOT_FOUND.getResponseMessage())
                    .build();
        } else {
            for (UserMstr mstr : UserMstrList) {
                userList.add(UserIdResponse.builder()
                        .userId(mstr.getUserId())
                        .loginId(mstr.getLoginId())
                        .corpId(mstr.getCorpId())
                        .rgstDate(dashDateFormat.format(mstr.getRgstDate()))
                        .build()
                );
            }
        }

        return FindUserDiResponse.builder()
                .userList(userList)
                .build();
    }

    public UserMstrChangePasswordResponse resetPassword(String loginId,
                                                        String newPassword,
                                                        String userDi) {
        UserMstr master = userMasterService.findLoginId(loginId, userDi);
        if (master == null) {
            throw new IllegalArgumentException(String.format("[%s] is not matched",
                    loginId));
        }
        master.setLoginPswd(encoder.encode(newPassword));
        master.setMngrDate(new Date());
        master.setFailCnt(0);
        master.setUserLock("N");
        return UserMstrChangePasswordResponse.builder().build();
    }

    public boolean checkPassword(String loginId, String userPswd) {
        UserMstr userMstr = userMasterService.checkId(loginId);
        if (userMstr == null) { //로그인 아이디가 가입된 아이디가 아니면 실패처리.
            return false;
        }
        if (encoder.matches(userPswd, userMstr.getLoginPswd())) {
            return true;
        } else {
            return false;
        }
    }

    public AccountInfo checkAccount(String loginPswd) {
        String loginId = SecurityContextHolder.getContext().getAuthentication().getName();
        UserMstr userMstr = userMasterService.findLoginId(loginId);
        if (checkPassword(loginId, loginPswd)) {

            //잠긴 계정의경우 비밀번호 매칭이 성공을 해도 로그인 못하도록 처리.
            if (StringUtils.equalsIgnoreCase(userMstr.getUserLock(), "Y")) {
                return AccountInfo.builder()
                        .success(false)
                        .code(AuthenticateExceptionType.AUTHENTICATE_LOCKED_ACCOUNT.getResponseCode())
                        .message(AuthenticateExceptionType.AUTHENTICATE_LOCKED_ACCOUNT.getResponseMessage())
                        .build();
            }

            //비밀번호 매칭 성공시 기존 실패건수와 잠김 해제.
            userMstr.setUserLock("N");
            userMstr.setFailCnt(0);
            return AccountInfo.builder()
                    .loginId(userMstr.getLoginId())
                    .failCnt(userMstr.getFailCnt())
                    .build();
        } else {
            //비밀번호 매칭이 실패하였고 시도한 아이디가 가입된 계정이면 실패건수 올리고 5회 이상 실패시 계정 잠금 처리.
            if (userMstr != null) {
                if (userMstr.getFailCnt() >= 5) {
                    userMstr.setUserLock("Y");
                } else {
                    userMstr.setFailCnt(userMstr.getFailCnt() + 1);
                }
            }
            return AccountInfo.builder()
                    .success(false)
                    .code(AuthenticateExceptionType.AUTHENTICATE_PASSWORD_DIFFERENT.getResponseCode())
                    .message(AuthenticateExceptionType.AUTHENTICATE_PASSWORD_DIFFERENT.getResponseMessage())
                    .failCnt(userMstr.getFailCnt())
                    .build();
        }

    }

    public void releaseSleep(ReleaseSleepRequest request) {
        List<UserMstrSleep> sleepList = userMasterSleepRepository.findAllByUserDi(request.getUserDi());
        if (sleepList.size() == 0) {
            throw new SsantalkRuntimeException(ApiResponseResultType.USER_NOT_FOUND.getResponseMessage(), ApiResponseResultType.USER_NOT_FOUND);
        }
        sleepList.forEach(s -> {
            UserMstr user = userMasterService.findById(s.getUserId()).orElse(null);
            if (user != null) {
                user.setAccountStatus(EnumTypes.UserAccountStatusType.NORMAL);
                user.setKeepAccountType(StringUtils.equalsIgnoreCase(request.getKeepAccount(), "Y") ? "Y" : "N");
            } else {
                throw new SsantalkRuntimeException(ApiResponseResultType.USER_NOT_FOUND.getResponseMessage(), ApiResponseResultType.USER_NOT_FOUND);
            }
        });
        userMasterSleepRepository.deleteAll(sleepList);
    }

    public UserDuplicateCheckResponse duplicateCheck(String userName, String phoneNumber) {
        List<UserMstr> result = userMasterService.checkUserNameAndPhoneNUmberDuplicate(userName, phoneNumber, (long) 0);

        return userDuplicateChecker(result);
    }

    public UserDuplicateCheckResponse duplicateDiCheck(String userDi) {
        List<UserMstr> result = userMasterService.checkUserDiDuplicate(userDi, (long) 0);

        return userDuplicateChecker(result);
    }

    private UserDuplicateCheckResponse userDuplicateChecker(List<UserMstr> result) {
        if (result.size() > 0) {
            return new ApiResponseGenerator<UserDuplicateCheckResponse>().success(UserDuplicateCheckResponse.builder()
                    .duplicateYn("Y")
                    .userName(result.get(0).getUserName())
                    .phoneNumber(result.get(0).getPhoneNumber())
                    .build());
        } else {
            return new ApiResponseGenerator<UserDuplicateCheckResponse>().success(UserDuplicateCheckResponse.builder()
                    .duplicateYn("N")
                    .build());
        }
    }

    public void deleteTokensCash(List<String> tokens) {
        for (String token : tokens) {
            cache.delete(token);
        }
    }
}
