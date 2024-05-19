package com.example.demo;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.data.jdbc.core.convert.JdbcCustomConversions;
import org.springframework.jdbc.datasource.lookup.JndiDataSourceLookup;

@SpringBootApplication
@PropertySource(value = "file:${VARIABLE_WS}/WsDemo.properties", ignoreResourceNotFound = true)
@EnableAutoConfiguration(exclude = { DataSourceAutoConfiguration.class,
    DataSourceTransactionManagerAutoConfiguration.class, HibernateJpaAutoConfiguration.class })
public class DemoApplication extends SpringBootServletInitializer{

	@Autowired
	private Environment env;
	
	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
		return application.sources(DemoApplication.class);
	}
	
	@Bean
	@Qualifier("dsUsuarios")
	public DataSource ds() {
		final JndiDataSourceLookup dsLookup = new JndiDataSourceLookup();
		dsLookup.setResourceRef(true);
		DataSource dataSource = (DataSource) dsLookup.getDataSource(env.getProperty("DSUSERS"));
		try {
			dataSource = (DataSource) dsLookup.getDataSource(env.getProperty("DSUSERS"));
			try (Connection connection = dataSource.getConnection()) {				
				System.out.println("Conexión establecida correctamente.");				
			}
		} catch (SQLException e) {		
			System.out.println("Error al establecer conexión: {}" + e.getMessage());		
		}
		return dataSource;
	}

	@Bean
	public JdbcCustomConversions jdbcCustomConversions() {
		List<Converter<?, ?>> converters = new ArrayList<>();
		return new JdbcCustomConversions(converters);
	}

}
