package gateway.api.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import gateway.api.model.Users;
import gateway.api.repository.UserRepository;



@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired
  UserRepository userRepository;

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String empId) throws UsernameNotFoundException {
    Users user = userRepository.findByEmpId(empId);
       // .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + empId));

    return UserDetailsImpl.build(user);
  }

}
