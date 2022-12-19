package gateway.api.bean;

import java.util.Date;
import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;

import lombok.Getter;
import lombok.Setter;
@Setter @Getter
public class UserDetailsWithToken {

	private int userId;
	private String empId;
	private String tokenString;
	private String email;
	private Date login;
	private String FullUsername;
	private List<String> roles;	

}