package project.ssantalk.application.service.component;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import tools.http.ResponseEntityBuildException;

/**
 * @author dragon
 * @since 2021. 04. 13.
 */
@Controller
public class ExceptionHandlingController {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleError(Exception ex) {
        return ex instanceof ResponseEntityBuildException ? new ResponseEntity<>(((ResponseEntityBuildException) ex).getStatus())
                : new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
