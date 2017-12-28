/*
 * Copyright 2014-2017 the original author or authors.
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

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.neo4j.ogm.session.SessionFactory;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests for {@link JdbcOperationsSessionRepository}.
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

//	@Mock
//	private DataSource dataSource;

//	@Mock
//	private JdbcOperations jdbcOperations;

	@Mock
	private SessionFactory sessionFactory;
	
//	@Mock
//	private PlatformTransactionManager transactionManager;

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

//	@Test
//	public void constructorNullJdbcOperations() {
//		this.thrown.expect(IllegalArgumentException.class);
//		this.thrown.expectMessage("Property 'sessionFactory' must not be null");
//
//		new OgmSessionRepository(null);
//	}

//	@Test
//	public void constructorNullTransactionManager() {
//		this.thrown.expect(IllegalArgumentException.class);
//		this.thrown.expectMessage("Property 'transactionManager' is required");
//
//		new OgmSessionRepository(this.session, null);
//	}

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

//	@Test
//	public void setCreateSessionAttributeQueryNull() {
//		this.thrown.expect(IllegalArgumentException.class);
//		this.thrown.expectMessage("Query must not be empty");
//
//		this.repository.setCreateSessionAttributeQuery(null);
//	}

//	@Test
//	public void setCreateSessionAttributeQueryEmpty() {
//		this.thrown.expect(IllegalArgumentException.class);
//		this.thrown.expectMessage("Query must not be empty");
//
//		this.repository.setCreateSessionAttributeQuery(" ");
//	}

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

//	@Test
//	public void setUpdateSessionAttributeQueryNull() {
//		this.thrown.expect(IllegalArgumentException.class);
//		this.thrown.expectMessage("Query must not be empty");
//
//		this.repository.setUpdateSessionAttributeQuery(null);
//	}

//	@Test
//	public void setUpdateSessionAttributeQueryEmpty() {
//		this.thrown.expect(IllegalArgumentException.class);
//		this.thrown.expectMessage("Query must not be empty");
//
//		this.repository.setUpdateSessionAttributeQuery(" ");
//	}

//	@Test
//	public void setDeleteSessionAttributeQueryNull() {
//		this.thrown.expect(IllegalArgumentException.class);
//		this.thrown.expectMessage("Query must not be empty");
//
//		this.repository.setDeleteSessionAttributeQuery(null);
//	}
//
//	@Test
//	public void setDeleteSessionAttributeQueryEmpty() {
//		this.thrown.expect(IllegalArgumentException.class);
//		this.thrown.expectMessage("Query must not be empty");
//
//		this.repository.setDeleteSessionAttributeQuery(" ");
//	}

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

//	@Test
//	public void setLobHandlerNull() {
//		this.thrown.expect(IllegalArgumentException.class);
//		this.thrown.expectMessage("LobHandler must not be null");
//
//		this.repository.setLobHandler(null);
//	}
//
//	@Test
//	public void setConversionServiceNull() {
//		this.thrown.expect(IllegalArgumentException.class);
//		this.thrown.expectMessage("conversionService must not be null");
//
//		this.repository.setConversionService(null);
//	}
//
//	@Test
//	public void createSessionDefaultMaxInactiveInterval() throws Exception {
//		JdbcOperationsSessionRepository.JdbcSession session = this.repository
//				.createSession();
//
//		assertThat(session.isNew()).isTrue();
//		assertThat(session.getMaxInactiveInterval())
//				.isEqualTo(new MapSession().getMaxInactiveInterval());
//		verifyZeroInteractions(this.session);
//	}
//
//	@Test
//	public void createSessionCustomMaxInactiveInterval() throws Exception {
//		int interval = 1;
//		this.repository.setDefaultMaxInactiveInterval(interval);
//
//		JdbcOperationsSessionRepository.JdbcSession session = this.repository
//				.createSession();
//
//		assertThat(session.isNew()).isTrue();
//		assertThat(session.getMaxInactiveInterval()).isEqualTo(Duration.ofSeconds(interval));
//		verifyZeroInteractions(this.session);
//	}
//
//	@Test
//	public void saveNewWithoutAttributes() {
//		JdbcOperationsSessionRepository.JdbcSession session = this.repository
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
//		JdbcOperationsSessionRepository.JdbcSession session = this.repository
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
//		JdbcOperationsSessionRepository.JdbcSession session = this.repository.new JdbcSession(
//				new MapSession());
//		session.setAttribute("testName", "testValue");
//
//		this.repository.save(session);
//
//		assertThat(session.isNew()).isFalse();
//		assertPropagationRequiresNew();
//		verify(this.session, times(1)).update(
//				and(startsWith("UPDATE"), contains("ATTRIBUTE_BYTES")),
//				isA(PreparedStatementSetter.class));
//	}
//
//	@Test
//	public void saveUpdatedLastAccessedTime() {
//		JdbcOperationsSessionRepository.JdbcSession session = this.repository.new JdbcSession(
//				new MapSession());
//		session.setLastAccessedTime(Instant.now());
//
//		this.repository.save(session);
//
//		assertThat(session.isNew()).isFalse();
//		assertPropagationRequiresNew();
//		verify(this.session, times(1)).update(
//				and(startsWith("UPDATE"), contains("LAST_ACCESS_TIME")),
//				isA(PreparedStatementSetter.class));
//	}
//
//	@Test
//	public void saveUnchanged() {
//		JdbcOperationsSessionRepository.JdbcSession session = this.repository.new JdbcSession(
//				new MapSession());
//
//		this.repository.save(session);
//
//		assertThat(session.isNew()).isFalse();
//		verifyZeroInteractions(this.session);
//	}
//
//	@Test
//	public void getSessionNotFound() {
//		String sessionId = "testSessionId";
//		given(this.session.query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class)))
//				.willReturn(Collections.emptyList());
//
//		JdbcOperationsSessionRepository.JdbcSession session = this.repository
//				.findById(sessionId);
//
//		assertThat(session).isNull();
//		assertPropagationRequiresNew();
//		verify(this.session, times(1)).query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class));
//	}
//
//	@Test
//	public void getSessionExpired() {
//		MapSession expired = new MapSession();
//		expired.setLastAccessedTime(Instant.now().minusSeconds(
//				MapSession.DEFAULT_MAX_INACTIVE_INTERVAL_SECONDS + 1));
//		given(this.session.query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class)))
//				.willReturn(Collections.singletonList(expired));
//
//		JdbcOperationsSessionRepository.JdbcSession session = this.repository
//				.findById(expired.getId());
//
//		assertThat(session).isNull();
//		assertPropagationRequiresNew();
//		verify(this.session, times(1)).query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class));
//		verify(this.session, times(1)).update(startsWith("DELETE"),
//				eq(expired.getId()));
//	}
//
//	@Test
//	public void getSessionFound() {
//		MapSession saved = new MapSession();
//		saved.setAttribute("savedName", "savedValue");
//		given(this.session.query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class)))
//				.willReturn(Collections.singletonList(saved));
//
//		JdbcOperationsSessionRepository.JdbcSession session = this.repository
//				.findById(saved.getId());
//
//		assertThat(session.getId()).isEqualTo(saved.getId());
//		assertThat(session.isNew()).isFalse();
//		assertThat(session.<String>getAttribute("savedName").orElse(null)).isEqualTo("savedValue");
//		assertPropagationRequiresNew();
//		verify(this.session, times(1)).query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class));
//	}
//
//	@Test
//	public void delete() {
//		String sessionId = "testSessionId";
//
//		this.repository.deleteById(sessionId);
//
//		assertPropagationRequiresNew();
//		verify(this.session, times(1)).update(startsWith("DELETE"), eq(sessionId));
//	}
//
//	@Test
//	public void findByIndexNameAndIndexValueUnknownIndexName() {
//		String indexValue = "testIndexValue";
//
//		Map<String, JdbcOperationsSessionRepository.JdbcSession> sessions = this.repository
//				.findByIndexNameAndIndexValue("testIndexName", indexValue);
//
//		assertThat(sessions).isEmpty();
//		verifyZeroInteractions(this.session);
//	}
//
//	@Test
//	public void findByIndexNameAndIndexValuePrincipalIndexNameNotFound() {
//		String principal = "username";
//		given(this.session.query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class)))
//				.willReturn(Collections.emptyList());
//
//		Map<String, JdbcOperationsSessionRepository.JdbcSession> sessions = this.repository
//				.findByIndexNameAndIndexValue(
//						FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
//						principal);
//
//		assertThat(sessions).isEmpty();
//		assertPropagationRequiresNew();
//		verify(this.session, times(1)).query(isA(String.class),
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
//		given(this.session.query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class)))
//				.willReturn(saved);
//
//		Map<String, JdbcOperationsSessionRepository.JdbcSession> sessions = this.repository
//				.findByIndexNameAndIndexValue(
//						FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
//						principal);
//
//		assertThat(sessions).hasSize(2);
//		assertPropagationRequiresNew();
//		verify(this.session, times(1)).query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class));
//	}
//
//	@Test
//	public void cleanupExpiredSessions() {
//		this.repository.cleanUpExpiredSessions();
//
//		assertPropagationRequiresNew();
//		verify(this.session, times(1)).update(startsWith("DELETE"), anyLong());
//	}
//
//	private void assertPropagationRequiresNew() {
//		ArgumentCaptor<TransactionDefinition> argument =
//				ArgumentCaptor.forClass(TransactionDefinition.class);
//		verify(this.transactionManager, atLeastOnce()).getTransaction(argument.capture());
//		assertThat(argument.getValue().getPropagationBehavior())
//				.isEqualTo(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
//	}

}
