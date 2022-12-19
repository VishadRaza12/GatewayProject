package gateway.api.model;

import java.util.Date;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "JWT_TOKEN")
public class JWTToken {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "ID")
	private Long id;

	
	@Column(name = "JWTTOKEN", length = 500)
	private String JWTtoken;

	// @NotBlank(message = "JWTREFRESHToken Is Mandatory")
	// @Column(name = "JWT_REFRESHTOKEN", length = 500)
	// private String JWTRefreshToken;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "USER_ID", referencedColumnName = "USER_ID")
	Users userId;

	@Column(name = "CREATEDON")
	private Date created;

}