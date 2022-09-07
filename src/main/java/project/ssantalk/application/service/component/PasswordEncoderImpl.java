package project.ssantalk.application.service.component;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * @author dragon
 * @since 2020. 10. 28.
 */
@Component
public class PasswordEncoderImpl
        extends
        BCryptPasswordEncoder {

    private static final Pattern BCRYPT_PATTERN = Pattern.compile("\\A\\$2a?\\$\\d\\d\\$[./0-9A-Za-z]{53}");

    private final Log logger = LogFactory.getLog(this.getClass());

    /**
     *
     */
    public PasswordEncoderImpl() {
        super(10);
    }

    public boolean isEncoded(String pwd) {
        return BCRYPT_PATTERN.matcher(pwd)
                .matches();
    }

    public String encIfRequire(String pwd) {
        if (isEncoded(pwd)) {
            return pwd;
        }

        return this.encode(pwd);
    }

    public String encode(String pwd,
                         String salt) {
        return BCrypt.hashpw(pwd,
                salt);
    }

    @Override
    public boolean matches(CharSequence rawPassword,
                           String encodedPassword) {
        if (encodedPassword == null || encodedPassword.length() == 0) {
            this.logger.warn("Empty encoded password");
            return false;
        }

        if (!BCRYPT_PATTERN.matcher(encodedPassword)
                .matches()) {
            this.logger.warn("Encoded password does not look like BCrypt");
            return false;
        }

        final String raw = rawPassword.toString();

        return BCRYPT_PATTERN.matcher(raw)
                .matches() ? equalsNoEarlyReturn(raw,
                encodedPassword)
                : BCrypt.checkpw(rawPassword.toString(),
                encodedPassword);
    }

    static boolean equalsNoEarlyReturn(String a,
                                       String b) {
        char[] caa = a.toCharArray();
        char[] cab = b.toCharArray();

        if (caa.length != cab.length) {
            return false;
        }

        byte ret = 0;
        for (int i = 0; i < caa.length; i++) { //
            ret |= caa[i] ^ cab[i];
        }
        return ret == 0;
    }

    /**
     * @param args
     * @throws Throwable
     */
    public static final void main(String[] args) throws Throwable {
        PasswordEncoderImpl encoder = new PasswordEncoderImpl();

        String encoded1 = encoder.encode("inzent");

        String encoded2 = BCrypt.hashpw("inzent",
                encoded1.substring(0,
                        30));
        System.out.println(encoded1);
        System.out.println(encoded2);

        System.out.println(equalsNoEarlyReturn("$2a$10$6bsFVulBUSP5qjEPDP/gMuyP/HnrBjiiN8WRR8MJM4hnRaMxnWQi2",
                BCrypt.hashpw("inzent",
                        "$2a$10$6bsFVulBUSP5qjEPDP/gMuyP/HnrBjiiN8WRR8MJM4hnRaMxnWQi2")));
    }
}
