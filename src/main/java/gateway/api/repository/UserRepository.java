package gateway.api.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import gateway.api.model.Role;
import gateway.api.model.Users;


@Repository
public interface UserRepository extends JpaRepository<Users, Long> {
 
  Users findByEmpId(String empId);

  @Query("select u.roles from Users u where u.empId=?1")
  List<Role> findRoleByUserId(String empId);



}
