package auth.authrestaurantlocator;

import auth.authrestaurantlocator.config.JwtService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.sql.DataSource;
import java.sql.SQLException;

@SpringBootApplication
@RequiredArgsConstructor
public class AuthRestaurantLocatorApplication {



	public static void main(String[] args) {
		SpringApplication.run(AuthRestaurantLocatorApplication.class, args);
	}





}
