package com.example.springsecurityjwt.contoller;

import com.example.springsecurityjwt.dto.ReqRes;
import com.example.springsecurityjwt.entity.Product;
import com.example.springsecurityjwt.repository.ProductRepo;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class AdminUsers {

    private final ProductRepo productRepo;

    @GetMapping("/public/products")
    public ResponseEntity<Object> getAllProducts() {
        return ResponseEntity.ok(productRepo.findAll());

    }

    @PostMapping("/admin/saveproduct")
    public ResponseEntity<Object> saveProduct(@RequestBody ReqRes productSaveRequest) {
        Product productToSave = new Product();
        productToSave.setName(productSaveRequest.getName());
        return ResponseEntity.ok(productRepo.save(productToSave));
    }


    @GetMapping ("/user/alone")
    public ResponseEntity<Object> userAlone() {
        return ResponseEntity.ok("Users alone can access this API only");
    }

    @GetMapping ("/adminuser/both")
    public ResponseEntity<Object> adminAndUsersApi() {
        return ResponseEntity.ok("All can use this API");
    }


    @GetMapping("/public/email")
    public String getCurrentUserEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println(authentication); //get all details(name,email,password,roles e.t.c) of the user
        System.out.println(authentication.getDetails()); // get remote ip
        System.out.println(authentication.getName()); //returns the email because the email is the unique identifier
        return authentication.getName(); // returns the email
    }


}
