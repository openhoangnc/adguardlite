/**
 * Every control-API call the interface makes, one function each.
 *
 * Grouped the way the API is, not the way the pages are, so a page that needs
 * two areas reaches into both rather than growing a third copy of a call.
 */
import { get, post, put } from './client';
import type {
    AccessList,
    BlocklistCatalogue,
    BlockedServices,
    CheckHostResult,
    Client,
    ClientsResponse,
    DnsConfig,
    Filter,
    FilteringStatus,
    InstallAddresses,
    Profile,
    QueryLog,
    QueryLogConfig,
    Rewrite,
    SafeSearchConfig,
    ServerStatus,
    ServiceCatalogue,
    Stats,
    StatsConfig,
    Theme,
    TlsConfig,
    TlsStatus,
    VersionInfo,
} from './types';

export * from './types';
export { ApiError } from './client';

/* Status, profile and version. */

export const getStatus = () => get<ServerStatus>('/status');
export const getProfile = () => get<Profile>('/profile');
export const updateProfile = (p: { language?: string; theme?: Theme }) => put<void>('/profile/update', p);
export const getVersion = (recheck = false) => post<VersionInfo>('/version.json', { recheck_now: recheck });
/** Installs the release the last check found, and restarts into it. */
export const installUpdate = () => post<{ new_version: string }>('/update', {});
export const login = (name: string, password: string) => post<void>('/login', { name, password });
export const logout = () => get<void>('/logout');

/* DNS settings. */

export const getDnsConfig = () => get<DnsConfig>('/dns_info');
export const setDnsConfig = (c: Partial<DnsConfig>) => post<void>('/dns_config', c);
export const setProtection = (enabled: boolean, duration?: number) =>
    post<void>('/protection', duration ? { enabled, duration } : { enabled });
export const clearCache = () => post<void>('/cache_clear');
export const testUpstream = (req: {
    upstream_dns: string[];
    bootstrap_dns: string[];
    fallback_dns: string[];
    private_upstream: string[];
}) => post<Record<string, string>>('/test_upstream_dns', req);

/* Filtering. */

export const getFilteringStatus = () => get<FilteringStatus>('/filtering/status');
export const setFilteringConfig = (enabled: boolean, interval: number) =>
    post<void>('/filtering/config', { enabled, interval });
export const addFilter = (name: string, url: string, whitelist: boolean) =>
    post<{ message?: string }>('/filtering/add_url', { name, url, whitelist });
export const removeFilter = (url: string, whitelist: boolean) => post<void>('/filtering/remove_url', { url, whitelist });
export const setFilter = (url: string, whitelist: boolean, data: Pick<Filter, 'name' | 'url' | 'enabled'>) =>
    post<void>('/filtering/set_url', { url, whitelist, data });
export const refreshFilters = (whitelist: boolean) => post<{ updated: number }>('/filtering/refresh', { whitelist });
export const setUserRules = (rules: string[]) => post<void>('/filtering/set_rules', { rules });
export const checkHost = (name: string) => get<CheckHostResult>('/filtering/check_host', { name });
export const getBlocklistCatalogue = () => get<BlocklistCatalogue>('/filtering/catalogue');

/* Safety toggles. */

export const getSafeSearch = () => get<SafeSearchConfig>('/safesearch/status');
export const setSafeSearch = (c: SafeSearchConfig) => put<void>('/safesearch/settings', c);

/* Rewrites. */

export const getRewrites = () => get<Rewrite[] | null>('/rewrite/list');
export const addRewrite = (r: Rewrite) => post<void>('/rewrite/add', r);
export const deleteRewrite = (r: Rewrite) => post<void>('/rewrite/delete', r);
export const updateRewrite = (target: Rewrite, update: Rewrite) => put<void>('/rewrite/update', { target, update });

/* Query log. */

export const getQueryLog = (params: {
    older_than?: string;
    limit?: number;
    offset?: number;
    search?: string;
    response_status?: string;
    filter_id?: string;
}) => get<QueryLog>('/querylog', params);
export const getQueryLogConfig = () => get<QueryLogConfig>('/querylog/config');
export const updateQueryLogConfig = (c: Partial<QueryLogConfig>) => put<void>('/querylog/config/update', c);
export const clearQueryLog = () => post<void>('/querylog_clear');

/* Statistics. */

export const getStats = () => get<Stats>('/stats');
export const getStatsConfig = () => get<StatsConfig>('/stats/config');
export const updateStatsConfig = (c: Partial<StatsConfig>) => put<void>('/stats/config/update', c);
export const resetStats = () => post<void>('/stats_reset');

/* Clients and access. */

export const getClients = () => get<ClientsResponse>('/clients');
export const addClient = (c: Client) => post<void>('/clients/add', c);
export const updateClient = (name: string, data: Client) => post<void>('/clients/update', { name, data });
export const deleteClient = (name: string) => post<void>('/clients/delete', { name });
export const getAccessList = () => get<AccessList>('/access/list');
export const setAccessList = (l: {
    allowed_clients: string[];
    disallowed_clients: string[];
    blocked_hosts: string[];
}) => post<void>('/access/set', l);

/* Blocked services. */

export const getServiceCatalogue = () => get<ServiceCatalogue>('/blocked_services/all');
export const getBlockedServices = () => get<BlockedServices>('/blocked_services/get');
export const updateBlockedServices = (b: BlockedServices) => put<void>('/blocked_services/update', b);

/* Encryption. */

export const getTlsStatus = () => get<TlsStatus>('/tls/status');
export const validateTls = (c: TlsConfig) => post<TlsStatus>('/tls/validate', c);
export const configureTls = (c: TlsConfig) => post<TlsStatus>('/tls/configure', c);

/* Setup wizard. */

export const getInstallAddresses = () => get<InstallAddresses>('/install/get_addresses');
export const checkInstallConfig = (req: {
    web: { ip: string; port: number; autofix: boolean };
    dns: { ip: string; port: number; autofix: boolean };
    set_static_ip: boolean;
}) =>
    post<{
        web: { status: string; can_autofix?: boolean };
        dns: { status: string; can_autofix?: boolean };
        static_ip: { static: string; ip: string; error: string };
    }>('/install/check_config', req);
export const configureInstall = (req: {
    web: { ip: string; port: number };
    dns: { ip: string; port: number };
    username: string;
    password: string;
}) => post<void>('/install/configure', req);
