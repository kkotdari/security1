package com.kot.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.kot.security1.model.User;

// CRUD 함수를 JpaRepository가 들고 있음
// @Repository가 없어도 빈으로 등록됨
public interface UserRepository extends JpaRepository<User, Integer>{
	public User findByUsername(String username); // JPA Query method 방식
}
