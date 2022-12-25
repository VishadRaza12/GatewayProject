package gateway.api.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import gateway.api.model.ServiceLog;

@Repository
public interface ServiceLogRepository extends JpaRepository<ServiceLog, Integer> {

}