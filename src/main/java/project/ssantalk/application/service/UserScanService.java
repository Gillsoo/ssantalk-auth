package project.ssantalk.application.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import project.ssantalk.entity.model.UserMstr;
import project.ssantalk.entity.repository.UserMasterService;
import project.ssantalk.entity.struct.UserRegisterTM.UserMasterScanTM;
import project.ssantalk.entity.struct.UserRegisterTM.UserPasswordChangeTM;
import project.ssantalk.entity.struct.UserRegisterTM.UserScanByPhoneNumberTM;

import javax.transaction.Transactional;
import java.util.List;

/**
 * @author dragon
 * @since 2021. 03. 15.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class UserScanService {
	final UserMasterService userMasterService;

	public List<UserMasterScanTM> scanByPhoneNumber(UserScanByPhoneNumberTM tm) {
		// TODO : 이 결과를 가지고 패스워드를 업데이트 하기 때문에 수정가능한 토큰을 발행하고 수정할 때 해당 토큰을 검증하도록 해야함.
		return userMasterService.findBy(UserMasterScanTM.class,
										UserMstr.builder()
												.phoneNumber(tm.getPhoneNumber())
												.build());
	}

	public void changeUserPassword(UserPasswordChangeTM tm) {
		userMasterService.changeUserPassword(	tm.getUserId(),
												tm.getPhoneNumber(),
												tm.getLoginPswd());
	}
}
