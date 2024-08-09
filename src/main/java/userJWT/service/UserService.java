package userJWT.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import userJWT.model.User;
import userJWT.repository.UserRepository;

@Service
public class UserService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private PasswordEncoder encoder;

    public void createUser(User user){
        String pass = user.getPassword();
        user.setPassword(encoder.encode(pass));
        repository.save(user);
    }
}