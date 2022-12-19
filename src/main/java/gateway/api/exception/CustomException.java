package gateway.api.exception;

import org.springframework.http.HttpStatus;

import org.springframework.http.ResponseEntity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class CustomException extends RuntimeException {

	 
	  private static final long serialVersionUID = 1L;

	  private final String message;
	  private final HttpStatus httpStatus;
	  private  Throwable cause;
	  private String statusCode;
	  private String extraMessage;
	  private int customerrorcode;
	  private int customerrordefid;
	  private ResponseEntity<Object> errorResponse;

	  public CustomException(String message, HttpStatus httpStatus, Throwable cause , String code) {
	    this.message = message;
	    this.httpStatus = httpStatus;
	    this.cause = cause;
	    this.statusCode = code;
	  }
		 
	  public CustomException(String message, HttpStatus httpStatus) {
	    this.message = message;
	    this.httpStatus = httpStatus;
	  }
	  
	  public CustomException(String message, HttpStatus httpStatus,int customerrorcode,int customerrordefid) {
		  this.message = message;
		  this.httpStatus = httpStatus;
		  this.customerrorcode =customerrorcode;
		  this.customerrordefid=customerrordefid;
	  }
	  
	  public CustomException(String message, HttpStatus httpStatus,int customerrorcode) {
	    this.message = message;
	    this.httpStatus = httpStatus;
	    this.customerrorcode = customerrorcode;
	  }
		
	  public CustomException(String message, HttpStatus httpStatus, String extraMessage, int customerrorcode) {
		super();
		this.message = message;
		this.httpStatus = httpStatus;
		this.extraMessage = extraMessage;
		this.customerrorcode = customerrorcode;
	}


	  public CustomException(String message, HttpStatus httpStatus,int customerrorcode,ResponseEntity<Object> errorResponse,Throwable cause) {
		  super();
		  this.message = message;
		  this.httpStatus = httpStatus;
	      this.errorResponse = errorResponse;
	  		this.customerrorcode = customerrorcode;
	  }
   
}
