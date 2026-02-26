import { createContext, useContext, useState } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import AgentChat from './pages/AgentChat';
import Tools from './pages/Tools';
import Cron from './pages/Cron';
import Integrations from './pages/Integrations';
import Memory from './pages/Memory';
import Config from './pages/Config';
import Profiles from './pages/Profiles';
import Providers from './pages/Providers';
import Channels from './pages/Channels';
import Cost from './pages/Cost';
import Logs from './pages/Logs';
import Doctor from './pages/Doctor';
import { AuthProvider } from './hooks/useAuth';
import { Locale, setLocale } from './lib/i18n';

type LocaleContextType = {
  locale: string;
  setAppLocale: (locale: string) => void;
};

export const LocaleContext = createContext<LocaleContextType>({
  locale: 'tr',
  setAppLocale: () => {},
});

export const useLocaleContext = () => useContext(LocaleContext);

function AppContent() {
  const [locale, setLocaleState] = useState('en');

  const setAppLocale = (newLocale: string) => {
    setLocaleState(newLocale);
    setLocale(newLocale as Locale);
  };

  return (
    <LocaleContext.Provider value={{ locale, setAppLocale }}>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/agent" element={<AgentChat />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/cron" element={<Cron />} />
          <Route path="/integrations" element={<Integrations />} />
          <Route path="/memory" element={<Memory />} />
          <Route path="/config" element={<Config />} />
          <Route path="/profiles" element={<Profiles />} />
          <Route path="/providers" element={<Providers />} />
          <Route path="/channels" element={<Channels />} />
          <Route path="/cost" element={<Cost />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/doctor" element={<Doctor />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </LocaleContext.Provider>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
