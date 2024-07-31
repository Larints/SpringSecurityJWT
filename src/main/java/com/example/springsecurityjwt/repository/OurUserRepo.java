package com.example.springsecurityjwt.repository;

import com.example.springsecurityjwt.entity.OurUsers;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OurUserRepo extends JpaRepository<OurUsers, Long> {

    Optional<OurUsers> findByEmail(String email);


}
