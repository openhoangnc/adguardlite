import { connect } from 'react-redux';

import { toggleProtection, getClients } from '../actions';
import { getStats, getStatsConfig } from '../actions/stats';
import { clearDnsCache } from '../actions/dnsConfig';
import { getAccessList } from '../actions/access';

import Dashboard from '../components/Dashboard';
import { RootState } from '../initialState';

const mapStateToProps = (state: RootState) => {
    const { dashboard, stats, access } = state;
    const props = { dashboard, stats, access };
    return props;
};

type DispatchProps = {
    toggleProtection: (...args: unknown[]) => unknown;
    getClients: (...args: unknown[]) => unknown;
    getStats: (...args: unknown[]) => unknown;
    getStatsConfig: (...args: unknown[]) => unknown;
    getAccessList: () => (dispatch: any) => void;
    clearDnsCache: (...args: unknown[]) => unknown;
};

const mapDispatchToProps: DispatchProps = {
    toggleProtection,
    getClients,
    getStats,
    getStatsConfig,
    getAccessList,
    clearDnsCache,
};

export default connect(mapStateToProps, mapDispatchToProps)(Dashboard);
