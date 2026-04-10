import { NextFunction, Router, Response } from 'express';
import { Container } from 'inversify';
import { AuthMiddleware } from '../../../libs/middlewares/auth.middleware';
import {
  addMessage,
  archiveConversation,
  archiveSearch,
  createConversation,
  deleteConversationById,
  deleteSearchById,
  deleteSearchHistory,
  getAllConversations,
  getConversationById,
  getSearchById,
  listAllArchivesConversation,
  regenerateAnswers,
  search,
  searchHistory,
  shareConversationById,
  shareSearch,
  unarchiveConversation,
  unarchiveSearch,
  unshareConversationById,
  unshareSearch,
  updateFeedback,
  updateTitle,
  streamChat,
  addMessageStream,
  createAgentConversation,
  streamAgentConversation,
  streamAgentConversationInternal,
  addMessageToAgentConversation,
  addMessageStreamToAgentConversation,
  addMessageStreamToAgentConversationInternal,
  getAllAgentConversations,
  getAgentConversationById,
  deleteAgentConversationById,
  createAgentTemplate,
  getAgentTemplate,
  deleteAgentTemplate,
  listAgentTemplates,
  createAgent,
  getAgent,
  deleteAgent,
  updateAgent,
  updateAgentTemplate,
  listAgents,
  getAvailableTools,
  shareAgent,
  unshareAgent,
  updateAgentPermissions,
  getAgentPermissions,
  regenerateAgentAnswers,
  streamChatInternal,
  addMessageStreamInternal,
} from '../controller/es_controller';
import { ValidationMiddleware } from '../../../libs/middlewares/validation.middleware';
import {
  conversationIdParamsSchema,
  enterpriseSearchCreateSchema,
  enterpriseSearchSearchSchema,
  enterpriseSearchSearchHistorySchema,
  searchIdParamsSchema,
  addMessageParamsSchema,
  conversationShareParamsSchema,
  conversationTitleParamsSchema,
  regenerateAnswersParamsSchema,
  updateFeedbackParamsSchema,
  searchShareParamsSchema,
  regenerateAgentAnswersParamsSchema,
} from '../validators/es_validators'; 
import { AppConfig, loadAppConfig } from '../../tokens_manager/config/config';
import { TokenScopes } from '../../../libs/enums/token-scopes.enum';
import { AuthenticatedServiceRequest } from '../../../libs/middlewares/types';
import { requireScopes } from '../../../libs/middlewares/require-scopes.middleware';
import { OAuthScopeNames } from '../../../libs/enums/oauth-scopes.enum';
import { KeyValueStoreService } from '../../../libs/services/keyValueStore.service';

export function createConversationalRouter(container: Container): Router {
  const router = Router();
  const authMiddleware = container.get<AuthMiddleware>('AuthMiddleware');
  let appConfig = container.get<AppConfig>('AppConfig');
  /**
   * @route POST /api/v1/conversations
   * @desc Create a new conversation with initial query
   * @access Private
   * @body {
   *   query: string
   * }
   */
  router.post(
    '/create',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_WRITE),
    ValidationMiddleware.validate(enterpriseSearchCreateSchema),
    createConversation(appConfig),
  );

  /**

   * @route POST /api/v1/conversations
   * @desc Create a new conversation with initial query
   * @access Private
   * @body {
   *   query: string
   * }
   */

  router.post(
    '/internal/create',
    authMiddleware.scopedTokenValidator(TokenScopes.CONVERSATION_CREATE),
    ValidationMiddleware.validate(enterpriseSearchCreateSchema),
    createConversation(appConfig),
  );

  /**
   * @route POST /api/v1/conversations/stream
   * @desc Stream chat events from AI backend
   * @access Private
   * @body {
   *   query: string
   *   previousConversations: array
   *   filters: object
   * }
   */
  router.post(
    '/stream',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_CHAT),
    ValidationMiddleware.validate(enterpriseSearchCreateSchema),
    streamChat(appConfig),
  );

  router.post(
    '/internal/stream',
    authMiddleware.scopedTokenValidator(TokenScopes.CONVERSATION_CREATE),
    ValidationMiddleware.validate(enterpriseSearchCreateSchema),
    streamChatInternal(appConfig),
  );

  /**
   * @route POST /api/v1/conversations/:conversationId/messages
   * @desc Add a new message to existing conversation
   * @access Private
   * @param {string} conversationId - Conversation ID
   * @body {
   *   query: string
   * }
   */
  router.post(
    '/:conversationId/messages',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_CHAT),
    ValidationMiddleware.validate(addMessageParamsSchema),
    addMessage(appConfig),
  );

  /**
   * @route POST /api/v1/conversations/:conversationId/messages
   * @desc Add a new message to existing conversation
   * @access Private
   * @param {string} conversationId - Conversation ID
   * @body {
   *   query: string
   * }
   */

  router.post(
    '/internal/:conversationId/messages',
    authMiddleware.scopedTokenValidator(TokenScopes.CONVERSATION_CREATE),
    ValidationMiddleware.validate(addMessageParamsSchema),
    addMessage(appConfig),
  );

  /**
   * @route POST /api/v1/conversations/:conversationId/messages/stream
   * @desc Stream message events from AI backend
   * @access Private
   * @param {string} conversationId - Conversation ID
   * @body {
   *   query: string
   * }
   */
  router.post(
    '/:conversationId/messages/stream',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_CHAT),
    ValidationMiddleware.validate(addMessageParamsSchema),
    addMessageStream(appConfig),
  );

  router.post(
    '/internal/:conversationId/messages/stream',
    authMiddleware.scopedTokenValidator(TokenScopes.CONVERSATION_CREATE),
    ValidationMiddleware.validate(addMessageParamsSchema),
    addMessageStreamInternal(appConfig),
  );

  /**
   * @route GET /api/v1/conversations/
   * @desc Get all conversations for a userId
   * @access Private
   * @param {string} conversationId - Conversation ID
   */
  router.get(
    '/',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_READ),
    getAllConversations,
  );

  /**
   * @route GET /api/v1/conversations/:conversationId
   * @desc Get conversation by ID
   * @access Private
   * @param {string} conversationId - Conversation ID
   */
  router.get(
    '/:conversationId',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_READ),
    ValidationMiddleware.validate(conversationIdParamsSchema),
    getConversationById,
  );

  /**
   * @route DELETE /api/v1/conversations/:conversationId
   * @desc Delete conversation by ID
   * @access Private
   * @param {string} conversationId - Conversation ID
   */
  router.delete(
    '/:conversationId',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_WRITE),
    ValidationMiddleware.validate(conversationIdParamsSchema),
    deleteConversationById,
  );

  /**
   * @route POST /api/v1/conversations/:conversationId/share
   * @desc Share conversation by ID
   * @access Private
   * @param {string} conversationId - Conversation ID
   */
  router.post(
    '/:conversationId/share',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_WRITE),
    ValidationMiddleware.validate(conversationShareParamsSchema),
    shareConversationById(appConfig),
  );

  /**
   * @route POST /api/v1/conversations/:conversationId/unshare
   * @desc Remove sharing access for specific users
   * @access Private
   * @param {string} conversationId - Conversation ID
   * @body {
   *   userIds: string[] - Array of user IDs to unshare with
   * }
   */
  router.post(
    '/:conversationId/unshare',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_WRITE),
    ValidationMiddleware.validate(conversationShareParamsSchema),
    unshareConversationById,
  );

  /**
   * @route POST /api/v1/conversations/:conversationId/message/:messageId/regenerate
   * @desc Regenerate message by ID
   * @access Private
   * @param {string} conversationId - Conversation ID
   * @param {string} messageId - Message ID
   */
  router.post(
    '/:conversationId/message/:messageId/regenerate',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_CHAT),
    ValidationMiddleware.validate(regenerateAnswersParamsSchema),
    regenerateAnswers(appConfig),
  );

  /**
   * @route PATCH /api/v1/conversations/:conversationId/title
   * @desc Update title for a conversation
   * @access Private
   * @param {string} conversationId - Conversation ID
   */
  router.patch(
    '/:conversationId/title',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_WRITE),
    ValidationMiddleware.validate(conversationTitleParamsSchema),
    updateTitle,
  );

  /**
   * @route POST /api/v1/conversations/:conversationId/message/:messageId/feedback
   * @desc Feedback message by ID
   * @access Private
   * @param {string} conversationId - Conversation ID
   * @param {string} messageId - Message ID
   */
  router.post(
    '/:conversationId/message/:messageId/feedback',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_WRITE),
    ValidationMiddleware.validate(updateFeedbackParamsSchema),
    updateFeedback,
  );

  /**
   * @route PATCH /api/v1/conversations/:conversationId/
   * @desc Archive Conversation by Conversation ID
   * @access Private
   * @param {string} conversationId - Conversation ID
   */
  router.patch(
    '/:conversationId/archive',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_WRITE),
    ValidationMiddleware.validate(conversationIdParamsSchema),
    archiveConversation,
  );

  /**
   * @route PATCH /api/v1/conversations/:conversationId/
   * @desc Archive Conversation by Conversation ID
   * @access Private
   * @param {string} conversationId - Conversation ID
   */
  router.patch(
    '/:conversationId/unarchive',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_WRITE),
    ValidationMiddleware.validate(conversationIdParamsSchema),
    unarchiveConversation,
  );

  /**
   * @route PATCH /api/v1/conversations/:conversationId/
   * @desc Archive Conversation by Conversation ID
   * @access Private
   * @param {string} conversationId - Conversation ID
   */
  router.get(
    '/show/archives',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.CONVERSATION_READ),
    listAllArchivesConversation,
  );

  return router;
}

export function createSemanticSearchRouter(container: Container): Router {
  const router = Router();
  const authMiddleware = container.get<AuthMiddleware>('AuthMiddleware');
  let appConfig = container.get<AppConfig>('AppConfig');

  router.post(
    '/',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.SEMANTIC_WRITE),
    ValidationMiddleware.validate(enterpriseSearchSearchSchema),
    search(appConfig),
  );

  router.get(
    '/',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.SEMANTIC_READ),
    ValidationMiddleware.validate(enterpriseSearchSearchHistorySchema),
    searchHistory,
  );

  router.get(
    '/:searchId',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.SEMANTIC_READ),
    ValidationMiddleware.validate(searchIdParamsSchema),
    getSearchById,
  );

  router.delete(
    '/:searchId',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.SEMANTIC_DELETE),
    ValidationMiddleware.validate(searchIdParamsSchema),
    deleteSearchById,
  );

  router.delete(
    '/',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.SEMANTIC_DELETE),
    deleteSearchHistory,
  );

  router.patch(
    '/:searchId/share',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.SEMANTIC_WRITE),
    ValidationMiddleware.validate(searchShareParamsSchema),
    shareSearch(appConfig),
  );

  router.patch(
    '/:searchId/unshare',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.SEMANTIC_WRITE),
    ValidationMiddleware.validate(searchShareParamsSchema),
    unshareSearch(appConfig),
  );

  router.patch(
    '/:searchId/archive',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.SEMANTIC_WRITE),
    ValidationMiddleware.validate(searchIdParamsSchema),
    archiveSearch,
  );

  router.patch(
    '/:searchId/unarchive',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.SEMANTIC_WRITE),
    ValidationMiddleware.validate(searchIdParamsSchema),
    unarchiveSearch,
  );

  router.post(
    '/updateAppConfig',
    authMiddleware.scopedTokenValidator(TokenScopes.FETCH_CONFIG),
    async (
      _req: AuthenticatedServiceRequest,
      res: Response,
      next: NextFunction,
    ) => {
      try {
        appConfig = await loadAppConfig();

        container
          .rebind<AppConfig>('AppConfig')
          .toDynamicValue(() => appConfig);

        res.status(200).json({
          message: 'User configuration updated successfully',
          config: appConfig,
        });
        return;
      } catch (error) {
        next(error);
      }
    },
  );

  return router;
}

export function createAgentConversationalRouter(container: Container): Router {
  const router = Router();
  const authMiddleware = container.get<AuthMiddleware>('AuthMiddleware');
  let appConfig = container.get<AppConfig>('AppConfig');
  const keyValueStoreService = container.isBound('KeyValueStoreService')
    ? container.get<KeyValueStoreService>('KeyValueStoreService')
    : undefined;

  router.post(
    '/:agentKey/conversations',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_EXECUTE),
    createAgentConversation(appConfig),
  );

  router.post(
    '/:agentKey/conversations/stream',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_EXECUTE),
    streamAgentConversation(appConfig),
  );

  router.post(
    '/:agentKey/conversations/:conversationId/messages',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_EXECUTE),
    addMessageToAgentConversation(appConfig),
  );

  router.post(
    '/:agentKey/conversations/:conversationId/messages/stream',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_EXECUTE),
    addMessageStreamToAgentConversation(appConfig),
  );

  router.post(
    '/:agentKey/conversations/internal/:conversationId/messages/stream',
    authMiddleware.scopedTokenValidator(TokenScopes.CONVERSATION_CREATE),
    // requireScopes(OAuthScopeNames.AGENT_EXECUTE),
    addMessageStreamToAgentConversationInternal(appConfig, keyValueStoreService),
  );

  router.post(
    '/:agentKey/conversations/internal/stream',
    authMiddleware.scopedTokenValidator(TokenScopes.CONVERSATION_CREATE),
    // requireScopes(OAuthScopeNames.AGENT_EXECUTE),
    streamAgentConversationInternal(appConfig, keyValueStoreService),
  );


    router.post(
      '/:agentKey/conversations/:conversationId/message/:messageId/regenerate',
      authMiddleware.authenticate,
      requireScopes(OAuthScopeNames.AGENT_EXECUTE),
      ValidationMiddleware.validate(regenerateAgentAnswersParamsSchema),
      regenerateAgentAnswers(appConfig),
    );
  

  router.get(
    '/:agentKey/conversations',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_READ),
    getAllAgentConversations,
  );

  router.get(
    '/:agentKey/conversations/:conversationId',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_READ),
    getAgentConversationById,
  );

  router.delete(
    '/:agentKey/conversations/:conversationId',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_WRITE),
    deleteAgentConversationById,
  );

  router.post(
    '/template',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_WRITE),
    createAgentTemplate(appConfig),
  );

  router.get(
    '/template/:templateId',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_READ),
    getAgentTemplate(appConfig),
  );

  router.put(
    '/template/:templateId',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_WRITE),
    updateAgentTemplate(appConfig),
  );

  router.delete(
    '/template/:templateId',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_WRITE),
    deleteAgentTemplate(appConfig),
  );

  router.get(
    '/template',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_READ),
    listAgentTemplates(appConfig),
  );

  router.post(
    '/create',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_WRITE),
    createAgent(appConfig),
  );

  router.get(
    '/:agentKey',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_READ),
    getAgent(appConfig),
  );

  router.put(
    '/:agentKey',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_WRITE),
    updateAgent(appConfig),
  );

  router.delete(
    '/:agentKey',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_WRITE),
    deleteAgent(appConfig),
  );

  router.get(
    '/',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_READ),
    listAgents(appConfig),
  );

  router.get(
    '/tools/list',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_READ),
    getAvailableTools(appConfig),
  );

  router.get(
    '/:agentKey/permissions',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_READ),
    getAgentPermissions(appConfig),
  );

  router.post(
    '/:agentKey/share',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_WRITE),
    shareAgent(appConfig),
  );

  router.post(
    '/:agentKey/unshare',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_WRITE),
    unshareAgent(appConfig),
  );

  router.put(
    '/:agentKey/permissions',
    authMiddleware.authenticate,
    requireScopes(OAuthScopeNames.AGENT_WRITE),
    updateAgentPermissions(appConfig),
  );

  return router;
} 

