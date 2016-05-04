package demo;

import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

@Service
class Users implements UserDetailsManager {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String password;
        List<GrantedAuthority> auth = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER");
        if (username.equals("Samwise")) {
            auth = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_HOBBIT");
            password = "TheShire";
        }
        else if (username.equals("Frodo")){
            auth = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_HOBBIT");
            password = "MyRing";
        }
        else{throw new UsernameNotFoundException("Username was not found. ");}
        return new org.springframework.security.core.userdetails.User(username, password, auth);
    }

    @Override
    public void createUser(UserDetails user) {// TODO Auto-generated method stub
    }

    @Override
    public void updateUser(UserDetails user) {// TODO Auto-generated method stub
    }

    @Override
    public void deleteUser(String username) {// TODO Auto-generated method stub
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        // TODO Auto-generated method stub
    }

    @Override
    public boolean userExists(String username) {
        // TODO Auto-generated method stub
        return false;
    }
}
