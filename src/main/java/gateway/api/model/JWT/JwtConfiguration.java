package gateway.api.model.JWT;



import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@AllArgsConstructor
@Getter
@Setter 
@NoArgsConstructor
@Table(name = "JWTCONFIGURATION")
public class JwtConfiguration {
    @Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "ID")
	private Integer id;

	@Column(name = "JWTSECRETKEY")
    private String jwtsecretkey;
    
    @Column(name = "JWTVALIDITY")
    private Long jwtvalidity;

	@Column(name = "JWTREFRESHTOKENVALIDITY")
    private Long jwtRefreshTokenValidity;

	@Column(name = "ENCRYPTIONALGORITHMNAME")
    private String encryptionalgorithmname;
    
    @Column(name = "ENCODINGALGORITHMNAME")
	private String encodingalgorithmname;
	
	@Column(name = "JWTALGORITHMNAME")
	private String jwtalgorithmname;
	
	@Column(name = "ENCRYPTIONSECRETKEY")
	private String encryptionsecretkey;

	@Column(name="InitializationVector")
	private String initializationvector;
}