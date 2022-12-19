package gateway.api.model;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Pattern.Flag;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "CONFIG_USERS")
public class Users {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "USER_ID")
	private Integer id;

	@NotBlank(message = "FirstName Is Mandatory")
	@Column(name = "FIRSTNAME", length = 250)
	private String firstName;

 
	@Column(name = "LASTNAME", length = 250)
	private String lastName;

 
	@Column(name = "NAME", length = 500)
	private String title;

	@NotBlank(message = "Employee ID Is Mandatory")
	@Column(name = "EMPID", length = 100, unique = true)
	private String empId;

 
	@Column(name = "IP", length = 250)
	private String ipAddress;

 
	@Column(name = "DESCRIPTION")
	private String description;

	

	@NotBlank(message = "Password Is Mandatory")
	@Column(name = "PASSWORD")
	private String password;

	@Column(name = "CONTACTNO", length = 100)
	private String contactNo;

	@Column(name = "EMAIL", length = 250)
	private String email;

	

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "CREATEDBY", referencedColumnName = "USER_ID")
	Users createdBy;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "UPDATEDBY", referencedColumnName = "USER_ID")
	Users updatedBy;

	

	@Column(name = "CREATEDON")
	private Date created;

	@Column(name = "UPDATEDON")
	private Date updated;

	@Column(name = "WORKSTATION")
	private String workStation;

	@Column(name = "REMARKS")
	private String remarks;

	@Column(name = "MAKER_CHECKER")
	private Boolean makerChecker;


	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(	name = "CONFIG_USERROLE", 
				joinColumns = @JoinColumn(name = "USER_ID"), 
				inverseJoinColumns = @JoinColumn(name = "ROLE_ID"))
	private Set<Role> roles = new HashSet<>();
	
	

}
