/*
 * Copyright 2014-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.session.data.neo4j.config.annotation.web.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import javax.sql.DataSource;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.beans.factory.UnsatisfiedDependencyException;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.convert.ConversionService;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.session.data.neo4j.OgmSessionRepository;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests for {@link OgmHttpSessionConfiguration}.
 *
 * @author Vedran Pavic
 * @author Eddú Meléndez
 * @author Eric Spiegelberg
 * @since 1.2.0
 */
public class OgmHttpSessionConfigurationTests {

	private static final String TABLE_NAME = "TEST_SESSION";

	private static final int MAX_INACTIVE_INTERVAL_IN_SECONDS = 600;

	private static final String LABEL_SYSTEM_PROPERTY = "spring.session.neo4j.label";

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	private AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();

	@After
	public void closeContext() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void noDataSourceConfiguration() {
		this.thrown.expect(UnsatisfiedDependencyException.class);
		this.thrown.expectMessage("springSessionOgmOperations");

		registerAndRefresh(EmptyConfiguration.class);
	}

	@Test
	public void defaultConfiguration() {
		registerAndRefresh(DefaultConfiguration.class);

		Object o = this.context.getBean(OgmSessionRepository.class);
		
		assertThat(this.context.getBean(OgmSessionRepository.class))
				.isNotNull();
	}

	@Test
	public void customLabel() {
		registerAndRefresh(CustomLabelConfiguration.class);

		OgmSessionRepository repository = this.context
				.getBean(OgmSessionRepository.class);
		assertThat(repository).isNotNull();
		assertThat(ReflectionTestUtils.getField(repository, "label"))
				.isEqualTo(TABLE_NAME);
	}

	@Test
	public void customLabelSystemProperty() {
		System.setProperty(LABEL_SYSTEM_PROPERTY, TABLE_NAME);

		try {
			registerAndRefresh(DefaultConfiguration.class);

			OgmSessionRepository repository = this.context
					.getBean(OgmSessionRepository.class);
			assertThat(repository).isNotNull();
			assertThat(ReflectionTestUtils.getField(repository, "label"))
					.isEqualTo(TABLE_NAME);
		}
		finally {
			System.clearProperty(LABEL_SYSTEM_PROPERTY);
		}
	}

	@Test
	public void setCustomLabelName() {
		registerAndRefresh(BaseConfiguration.class,
				CustomLabelSetConfiguration.class);

		OgmHttpSessionConfiguration repository = this.context
				.getBean(OgmHttpSessionConfiguration.class);
		assertThat(repository).isNotNull();
		assertThat(ReflectionTestUtils.getField(repository, "label")).isEqualTo(
				"custom_session");
	}
	
	@Test
	public void setCustomMaxInactiveIntervalInSeconds() {
		registerAndRefresh(BaseConfiguration.class,
				CustomMaxInactiveIntervalInSecondsSetConfiguration.class);

		OgmHttpSessionConfiguration repository = this.context
				.getBean(OgmHttpSessionConfiguration.class);
		assertThat(repository).isNotNull();
		assertThat(ReflectionTestUtils.getField(repository, "maxInactiveIntervalInSeconds")).isEqualTo(
				10);
	}

	@Test
	public void customMaxInactiveIntervalInSeconds() {
		registerAndRefresh(CustomMaxInactiveIntervalInSecondsConfiguration.class);

		OgmSessionRepository repository = this.context
				.getBean(OgmSessionRepository.class);
		assertThat(repository).isNotNull();
		assertThat(ReflectionTestUtils.getField(repository, "defaultMaxInactiveInterval"))
				.isEqualTo(MAX_INACTIVE_INTERVAL_IN_SECONDS);
	}

	@Test
	public void customConversionServiceConfiguration() {
		registerAndRefresh(CustomConversionServiceConfiguration.class);

		OgmSessionRepository repository = this.context
				.getBean(OgmSessionRepository.class);
		ConversionService conversionService = this.context
				.getBean("springSessionConversionService", ConversionService.class);
		assertThat(repository).isNotNull();
		assertThat(conversionService).isNotNull();
		Object repositoryConversionService = ReflectionTestUtils.getField(repository,
				"conversionService");
		assertThat(repositoryConversionService).isEqualTo(conversionService);
	}

	@Test
	public void resolveLabelByPropertyPlaceholder() {
		this.context.setEnvironment(new MockEnvironment().withProperty("session.neo4j.label", "custom_session_table"));
		registerAndRefresh(CustomOgmHttpSessionConfiguration.class);
		OgmHttpSessionConfiguration configuration = this.context.getBean(OgmHttpSessionConfiguration.class);
		assertThat(ReflectionTestUtils.getField(configuration, "label")).isEqualTo("custom_session_table");
	}

	private void registerAndRefresh(Class<?>... annotatedClasses) {
		this.context.register(annotatedClasses);
		this.context.refresh();
	}

	@Configuration
	@EnableOgmHttpSession
	static class EmptyConfiguration {
	}

	static class BaseConfiguration {

		@Bean
		public DataSource dataSource() {
			return mock(DataSource.class);
		}

	}

	@Configuration
	@EnableOgmHttpSession
	static class DefaultConfiguration extends BaseConfiguration {
	}

	@Configuration
	@EnableOgmHttpSession(label = TABLE_NAME)
	static class CustomLabelConfiguration extends BaseConfiguration {
	}

	@Configuration
	static class CustomLabelSetConfiguration extends OgmHttpSessionConfiguration {

		CustomLabelSetConfiguration() {
			setLabel("custom_session");
		}

	}

	@Configuration
	static class CustomMaxInactiveIntervalInSecondsSetConfiguration extends OgmHttpSessionConfiguration {

		CustomMaxInactiveIntervalInSecondsSetConfiguration() {
			setMaxInactiveIntervalInSeconds(10);
		}

	}

	@Configuration
	@EnableOgmHttpSession(maxInactiveIntervalInSeconds = MAX_INACTIVE_INTERVAL_IN_SECONDS)
	static class CustomMaxInactiveIntervalInSecondsConfiguration
			extends BaseConfiguration {
	}

	@Configuration
	@EnableOgmHttpSession
	static class CustomConversionServiceConfiguration extends BaseConfiguration {

		@Bean
		public ConversionService springSessionConversionService() {
			return mock(ConversionService.class);
		}

	}

	@Configuration
	@EnableOgmHttpSession(label = "${session.neo4j.label}")
	static class CustomOgmHttpSessionConfiguration extends BaseConfiguration {

		@Bean
		public PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
			return new PropertySourcesPlaceholderConfigurer();
		}

	}

}
