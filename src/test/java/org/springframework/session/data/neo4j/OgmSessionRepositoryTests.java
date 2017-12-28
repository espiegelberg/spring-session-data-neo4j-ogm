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
package org.springframework.session.data.neo4j;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyZeroInteractions;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.neo4j.ogm.model.Result;
import org.neo4j.ogm.response.model.NodeModel;
import org.neo4j.ogm.response.model.QueryResultModel;
import org.neo4j.ogm.response.model.QueryStatisticsModel;
import org.neo4j.ogm.session.Session;
import org.neo4j.ogm.session.SessionFactory;
import org.neo4j.ogm.transaction.Transaction;
import org.springframework.session.MapSession;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests for {@link OgmSessionRepository}.
 *
 * @author Eric Spiegelberg
 * @author Vedran Pavic
 * @since 1.2.0
 */
@RunWith(MockitoJUnitRunner.class)
public class OgmSessionRepositoryTests {

	private static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Mock
	private Session session;

	@Mock
	private Transaction transaction;
	
	@Mock
	private SessionFactory sessionFactory;
	
	private OgmSessionRepository repository;
	
	@Before
	public void setUp() {
		this.repository = new OgmSessionRepository(this.sessionFactory);
	}

	@Test
	public void constructorSessionFactory() {
		OgmSessionRepository repository = new OgmSessionRepository(this.sessionFactory);

		assertThat(ReflectionTestUtils.getField(repository, "sessionFactory"))
				.isNotNull();
	}

	@Test
	public void constructorNullSessionFactory() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Property 'sessionFactory' must not be null");

		new OgmSessionRepository(null);
	}

	@Test
	public void setLabelNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Label must not be empty");

		this.repository.setLabel(null);
	}

	@Test
	public void setLabelEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Label must not be empty");

		this.repository.setLabel(" ");
	}

	@Test
	public void setCreateSessionQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setCreateSessionQuery(null);
	}

	@Test
	public void setCreateSessionQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setCreateSessionQuery(" ");
	}

	@Test
	public void setGetSessionQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setGetSessionQuery(null);
	}

	@Test
	public void setGetSessionQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setGetSessionQuery(" ");
	}

	@Test
	public void setUpdateSessionQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setUpdateSessionQuery(null);
	}

	@Test
	public void setUpdateSessionQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setUpdateSessionQuery(" ");
	}

	@Test
	public void setDeleteSessionQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setDeleteSessionQuery(null);
	}

	@Test
	public void setDeleteSessionQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setDeleteSessionQuery(" ");
	}

	@Test
	public void setListSessionsByPrincipalNameQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setListSessionsByPrincipalNameQuery(null);
	}

	@Test
	public void setListSessionsByPrincipalNameQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setListSessionsByPrincipalNameQuery(" ");
	}

	@Test
	public void setDeleteSessionsByLastAccessTimeQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setDeleteSessionsByLastAccessTimeQuery(null);
	}

	@Test
	public void setDeleteSessionsByLastAccessTimeQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setDeleteSessionsByLastAccessTimeQuery(" ");
	}

	@Test
	public void setConversionServiceNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("conversionService must not be null");

		this.repository.setConversionService(null);
	}

	@Test
	public void createSessionDefaultMaxInactiveInterval() throws Exception {
		OgmSessionRepository.OgmSession session = this.repository.createSession();
		
		assertThat(session.isNew()).isTrue();
		assertThat(session.getMaxInactiveInterval())
				.isEqualTo(new MapSession().getMaxInactiveInterval());
		verifyZeroInteractions(this.sessionFactory);
	}

	@Test
	public void createSessionCustomMaxInactiveInterval() throws Exception {
		int interval = 1;
		this.repository.setDefaultMaxInactiveInterval(interval);

		OgmSessionRepository.OgmSession session = this.repository
				.createSession();

		assertThat(session.isNew()).isTrue();
		assertThat(session.getMaxInactiveInterval()).isEqualTo(Duration.ofSeconds(interval));
		verifyZeroInteractions(this.sessionFactory);
	}

//	@Test
//	public void saveNewWithoutAttributes() {
//		OgmSessionRepository.OgmSession session = this.repository
//				.createSession();
//
//		this.repository.save(session);
//
//		assertThat(session.isNew()).isFalse();
//		assertPropagationRequiresNew();
//		verify(this.session, times(1)).update(startsWith("INSERT"),
//				isA(PreparedStatementSetter.class));
//		verifyNoMoreInteractions(this.session);
//	}
//
//	@Test
//	public void saveNewWithAttributes() {
//		OgmSessionRepository.OgmSession session = this.repository
//				.createSession();
//		session.setAttribute("testName", "testValue");
//
//		this.repository.save(session);
//
//		assertThat(session.isNew()).isFalse();
//		assertPropagationRequiresNew();
//		verify(this.session, times(1)).update(startsWith("INSERT"),
//				isA(PreparedStatementSetter.class));
//		verify(this.session, times(1)).batchUpdate(
//				and(startsWith("INSERT"), contains("ATTRIBUTE_BYTES")),
//				isA(BatchPreparedStatementSetter.class));
//	}
//
//	@Test
//	public void saveUpdatedAttributes() {
//		OgmSessionRepository.OgmSession session = this.repository.new JdbcSession(
//				new MapSession());
//		session.setAttribute("testName", "testValue");
//
//		this.repository.save(session);
//
//		assertThat(session.isNew()).isFalse();
//		assertPropagationRequiresNew();
//		verify(this.sessionFactory, times(1)).update(
//				and(startsWith("UPDATE"), contains("ATTRIBUTE_BYTES")),
//				isA(PreparedStatementSetter.class));
//	}
//
//	@Test
//	public void saveUpdatedLastAccessedTime() {
//		OgmSessionRepository.OgmSession session = this.repository.new JdbcSession(
//				new MapSession());
//		session.setLastAccessedTime(Instant.now());
//
//		this.repository.save(session);
//
//		assertThat(session.isNew()).isFalse();
//		assertPropagationRequiresNew();
//		verify(this.sessionFactory, times(1)).update(
//				and(startsWith("UPDATE"), contains("LAST_ACCESS_TIME")),
//				isA(PreparedStatementSetter.class));
//	}
//
//	@Test
//	public void saveUnchanged() {
//		OgmSessionRepository.OgmSession session = this.repository.new JdbcSession(
//				new MapSession());
//
//		this.repository.save(session);
//
//		assertThat(session.isNew()).isFalse();
//		verifyZeroInteractions(this.sessionFactory);
//	}

	@Test
	public void getSessionNotFound() {
		String sessionId = "testSessionId";

		given(this.sessionFactory.openSession()).willReturn(session);		
		given(session.beginTransaction()).willReturn(transaction);
		
		List<Map<String, Object>> r = new ArrayList<>();
		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);
		
		OgmSessionRepository.OgmSession session = this.repository
				.getSession(sessionId);

		assertThat(session).isNull();
		verify(this.sessionFactory, times(1)).openSession(); 
		verify(this.session, times(1)).beginTransaction();
		verify(this.transaction, times(1)).commit();
		verify(this.transaction, times(1)).close();
	}
	
	@Test
	public void getSessionFound() {
		
		given(this.sessionFactory.openSession()).willReturn(session);		
		given(session.beginTransaction()).willReturn(transaction);
		
		List<Map<String, Object>> r = new ArrayList<>();
		
		String attributeName = "name";
		String attributeValue = "Elizabeth";
		
		Map<String, Object> data = new HashMap<>();
		NodeModel nodeModel = new NodeModel();
		Map<String, Object> properties = new HashMap<>();
		long now = new Date().getTime();
		properties.put(OgmSessionRepository.CREATION_TIME, now);
		properties.put(OgmSessionRepository.LAST_ACCESS_TIME, now);
		properties.put(OgmSessionRepository.MAX_INACTIVE_INTERVAL, 999);
		properties.put(OgmSessionRepository.ATTRIBUTE_KEY_PREFIX + attributeName, attributeValue);
		nodeModel.setProperties(properties);
		data.put("n", nodeModel);
		r.add(data);
		
		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);
		
		MapSession saved = new MapSession();
		saved.setAttribute(attributeName, attributeValue);

		OgmSessionRepository.OgmSession session = this.repository
				.getSession(saved.getId());

		assertThat(session).isNotNull();
		
		assertThat(session.getId()).isEqualTo(saved.getId());
		assertThat(session.isNew()).isFalse();

		assertThat(session.<String>getAttribute(attributeName).orElse(null)).isEqualTo(attributeValue);
		
		verify(this.sessionFactory, times(1)).openSession(); 
		verify(this.session, times(1)).beginTransaction();
		verify(this.transaction, times(1)).commit();
		verify(this.transaction, times(1)).close();
		
	}

//	@Test
//	public void getSessionExpired() {
//		MapSession expired = new MapSession();
//		expired.setLastAccessedTime(Instant.now().minusSeconds(
//				MapSession.DEFAULT_MAX_INACTIVE_INTERVAL_SECONDS + 1));
//		given(this.sessionFactory.query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class)))
//				.willReturn(Collections.singletonList(expired));
//
//		OgmSessionRepository.OgmSession session = this.repository
//				.getSession(expired.getId());
//
//		assertThat(session).isNull();
//		assertPropagationRequiresNew();
//		verify(this.sessionFactory, times(1)).query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class));
//		verify(this.sessionFactory, times(1)).update(startsWith("DELETE"),
//				eq(expired.getId()));
//	}
//
//
//	@Test
//	public void delete() {
//		String sessionId = "testSessionId";
//
//		this.repository.deleteById(sessionId);
//
//		assertPropagationRequiresNew();
//		verify(this.sessionFactory, times(1)).update(startsWith("DELETE"), eq(sessionId));
//	}
//
//	@Test
//	public void findByIndexNameAndIndexValueUnknownIndexName() {
//		String indexValue = "testIndexValue";
//
//		Map<String, OgmSessionRepository.OgmSession> sessions = this.repository
//				.findByIndexNameAndIndexValue("testIndexName", indexValue);
//
//		assertThat(sessions).isEmpty();
//		verifyZeroInteractions(this.sessionFactory);
//	}
//
//	@Test
//	public void findByIndexNameAndIndexValuePrincipalIndexNameNotFound() {
//		String principal = "username";
//		given(this.sessionFactory.query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class)))
//				.willReturn(Collections.emptyList());
//
//		Map<String, OgmSessionRepository.OgmSession> sessions = this.repository
//				.findByIndexNameAndIndexValue(
//						FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
//						principal);
//
//		assertThat(sessions).isEmpty();
//		assertPropagationRequiresNew();
//		verify(this.sessionFactory, times(1)).query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class));
//	}
//
//	@Test
//	public void findByIndexNameAndIndexValuePrincipalIndexNameFound() {
//		String principal = "username";
//		Authentication authentication = new UsernamePasswordAuthenticationToken(principal,
//				"notused", AuthorityUtils.createAuthorityList("ROLE_USER"));
//		List<MapSession> saved = new ArrayList<>(2);
//		MapSession saved1 = new MapSession();
//		saved1.setAttribute(SPRING_SECURITY_CONTEXT, authentication);
//		saved.add(saved1);
//		MapSession saved2 = new MapSession();
//		saved2.setAttribute(SPRING_SECURITY_CONTEXT, authentication);
//		saved.add(saved2);
//		given(this.sessionFactory.query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class)))
//				.willReturn(saved);
//
//		Map<String, OgmSessionRepository.OgmSession> sessions = this.repository
//				.findByIndexNameAndIndexValue(
//						FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
//						principal);
//
//		assertThat(sessions).hasSize(2);
//		assertPropagationRequiresNew();
//		verify(this.sessionFactory, times(1)).query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class));
//	}

//	@Test
//	public void cleanupExpiredSessions() {
//		this.repository.cleanUpExpiredSessions();
//
//		//assertPropagationRequiresNew();
//		verify(this.sessionFactory, times(1)).update(startsWith("DELETE"), anyLong());
//	}

//	@Test
//	public void primative() {
//
//		Object value = Integer.parseInt("1");
//		boolean suppored = isNeo4jSupportedType(value);
//		Assert.assertTrue(suppored);
//		
//		value = new Long(2).longValue();
//		suppored = isNeo4jSupportedType(value);
//		Assert.assertTrue(suppored);
//		
//		value = Float.parseFloat("1.0");
//		suppored = isNeo4jSupportedType(value);
//		Assert.assertTrue(suppored);
//		
//		value = Double.parseDouble("1.0");
//		suppored = isNeo4jSupportedType(value);
//		Assert.assertTrue(suppored);
//		
//		value = new Boolean(true).booleanValue();
//		suppored = isNeo4jSupportedType(value);
//		Assert.assertTrue(suppored);
//		
//		value = new byte['a'];
//		suppored = isNeo4jSupportedType(value);
//		Assert.assertTrue(suppored);
//		
//		value = "test".getBytes();
//		suppored = isNeo4jSupportedType(value);
//		Assert.assertTrue(suppored);
//		
//		value = new Boolean[] { true, false };
//		suppored = isNeo4jSupportedType(value);
//		Assert.assertTrue(suppored);
//		
//		value = "Test";
//		suppored = isNeo4jSupportedType(value);
//		Assert.assertTrue(suppored);
//		
//		value = new String[] { "Test1", "Test2" };
//		suppored = isNeo4jSupportedType(value);
//		Assert.assertTrue(suppored);
//		
//	}
//	
//	/**
//	 * Property values in Neo4j could be either Java primitive types (float, double, int, boolean, byte,... ), Strings or array of both.
//	 * 
//	 * @param o The object to evaluate.
//	 * @return boolean true if the object is a Neo4j supported data type otherwise false.
//	 */
//	protected boolean isNeo4jSupportedType(Object o) {
//	
//		Class<?> clazz = o.getClass();
//		boolean supported = ClassUtils.isPrimitiveOrWrapper(clazz);
//		
//		if (!supported) {
//			supported = ClassUtils.isPrimitiveWrapperArray(clazz);	
//		}
//
//		if (!supported) {
//			supported = o instanceof byte[];	
//		}
//		
//		if (!supported) {
//			supported = o instanceof String;	
//		}
//		
//		if (!supported) {
//			supported = o instanceof String[];	
//		}
//		
//		return supported;
//		
//	}
	
	
}
