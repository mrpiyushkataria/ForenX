import React, { useState, useEffect } from 'react';
import { 
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer 
} from 'recharts';
import { 
  Activity, Shield, AlertTriangle, Globe, 
  Users, Database, Cpu, Download 
} from 'react-icons';
import { motion } from 'framer-motion';
import toast from 'react-hot-toast';

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalLogs: 0,
    suspiciousEndpoints: 0,
    highRiskIPs: 0,
    activeThreats: 0,
    dataProcessed: 0,
    alerts24h: 0
  });
  
  const [timelineData, setTimelineData] = useState([]);
  const [threatDistribution, setThreatDistribution] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8'];

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const [statsRes, timelineRes, threatsRes, alertsRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/timeline?hours=24'),
        fetch('/api/threats/distribution'),
        fetch('/api/alerts/recent?limit=5')
      ]);

      const [statsData, timelineData, threatsData, alertsData] = await Promise.all([
        statsRes.json(),
        timelineRes.json(),
        threatsRes.json(),
        alertsRes.json()
      ]);

      setStats(statsData);
      setTimelineData(timelineData);
      setThreatDistribution(threatsData);
      setRecentAlerts(alertsData);
    } catch (error) {
      toast.error('Failed to fetch dashboard data');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const StatCard = ({ title, value, icon: Icon, color, change }) => (
    <motion.div
      whileHover={{ scale: 1.02 }}
      className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-500 dark:text-gray-400 text-sm">{title}</p>
          <p className="text-3xl font-bold mt-2">{value}</p>
          {change && (
            <p className={`text-sm mt-1 ${change > 0 ? 'text-green-500' : 'text-red-500'}`}>
              {change > 0 ? '↑' : '↓'} {Math.abs(change)}%
            </p>
          )}
        </div>
        <div className={`p-3 rounded-full ${color}`}>
          <Icon className="w-8 h-8 text-white" />
        </div>
      </div>
    </motion.div>
  );

  const AlertBadge = ({ severity }) => {
    const colors = {
      critical: 'bg-red-100 text-red-800',
      high: 'bg-orange-100 text-orange-800',
      medium: 'bg-yellow-100 text-yellow-800',
      low: 'bg-blue-100 text-blue-800'
    };
    
    return (
      <span className={`px-2 py-1 rounded-full text-xs font-semibold ${colors[severity] || colors.low}`}>
        {severity.toUpperCase()}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            ForenX Sentinel Dashboard
          </h1>
          <p className="text-gray-500 dark:text-gray-400">
            Real-time security monitoring & threat intelligence
          </p>
        </div>
        <div className="flex space-x-4">
          <button className="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600">
            <Download className="inline mr-2" />
            Export Report
          </button>
          <button className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">
            Settings
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <StatCard
          title="Total Logs Processed"
          value={stats.totalLogs.toLocaleString()}
          icon={Database}
          color="bg-blue-500"
          change={12}
        />
        <StatCard
          title="Suspicious Endpoints"
          value={stats.suspiciousEndpoints}
          icon={AlertTriangle}
          color="bg-red-500"
          change={-5}
        />
        <StatCard
          title="High Risk IPs"
          value={stats.highRiskIPs}
          icon={Shield}
          color="bg-orange-500"
          change={8}
        />
        <StatCard
          title="Active Threats"
          value={stats.activeThreats}
          icon={Activity}
          color="bg-purple-500"
          change={15}
        />
        <StatCard
          title="Data Processed"
          value={`${(stats.dataProcessed / 1024 / 1024).toFixed(1)} GB`}
          icon={Cpu}
          color="bg-green-500"
          change={23}
        />
        <StatCard
          title="Alerts (24h)"
          value={stats.alerts24h}
          icon={Users}
          color="bg-indigo-500"
          change={-3}
        />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Timeline Chart */}
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
          <h3 className="text-lg font-semibold mb-4">Activity Timeline (24h)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="requests" 
                stroke="#3b82f6" 
                strokeWidth={2}
              />
              <Line 
                type="monotone" 
                dataKey="threats" 
                stroke="#ef4444" 
                strokeWidth={2}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Threat Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
          <h3 className="text-lg font-semibold mb-4">Threat Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={threatDistribution}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {threatDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip formatter={(value) => [value, 'Count']} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-semibold">Recent Security Alerts</h3>
          <button className="text-blue-500 hover:text-blue-600">View All →</button>
        </div>
        
        <div className="space-y-4">
          {recentAlerts.map((alert, index) => (
            <motion.div
              key={alert.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              <div className="flex items-center space-x-4">
                <AlertBadge severity={alert.severity} />
                <div>
                  <p className="font-medium">{alert.title}</p>
                  <p className="text-sm text-gray-500">{alert.description}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-sm text-gray-500">{alert.time}</p>
                <p className="text-sm">{alert.source}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <button className="p-4 bg-blue-500 text-white rounded-lg hover:bg-blue-600">
          <Globe className="w-6 h-6 mx-auto mb-2" />
          IP Threat Lookup
        </button>
        <button className="p-4 bg-green-500 text-white rounded-lg hover:bg-green-600">
          <Database className="w-6 h-6 mx-auto mb-2" />
          Upload Logs
        </button>
        <button className="p-4 bg-purple-500 text-white rounded-lg hover:bg-purple-600">
          <Activity className="w-6 h-6 mx-auto mb-2" />
          Real-time Monitor
        </button>
        <button className="p-4 bg-red-500 text-white rounded-lg hover:bg-red-600">
          <Shield className="w-6 h-6 mx-auto mb-2" />
          Generate Report
        </button>
      </div>
    </div>
  );
};

export default Dashboard;
