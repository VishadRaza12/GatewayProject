package gateway.api.model;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import gateway.api.UtitlityFunctions.Constants;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@AllArgsConstructor
@Getter
@Setter
@NoArgsConstructor
@Table(name = "ServiceLog")
@JsonIgnoreProperties(ignoreUnknown = true, value = { "hibernateLazyInitializer", "handler" }, allowSetters = true)
public class ServiceLog {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id")
	private Integer id;
	
	@Column(name = "requestId")
	private String requestId;
	
	@Column(name = "url")
	private String url;
	
	@Column(name = "header")
	private String header;
	
	@Column(name = "methodType")
	private String methodType;
	
	@Column(name = "requestTime")
	private Date requestTime;
	
	@Column(name = "request", columnDefinition = Constants.NVARCHAR_MAX)
	private String request;
	
	@Column(name = "responseTime")
	private Date responseTime;
	
	@Column(name = "response", columnDefinition = Constants.NVARCHAR_MAX)
	private String response;
	
}
