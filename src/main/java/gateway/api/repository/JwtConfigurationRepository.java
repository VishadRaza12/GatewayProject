package gateway.api.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import gateway.api.model.JWT.JwtConfiguration;



public interface JwtConfigurationRepository extends JpaRepository<JwtConfiguration, Long> {

    public JwtConfiguration findTopByOrderByIdAsc();

}