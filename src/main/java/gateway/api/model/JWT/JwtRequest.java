package gateway.api.model.JWT;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class JwtRequest implements Serializable {

	private static final long serialVersionUID = 5926468583005150707L;
	
	private String empID;
	private String Pswd;
	
}