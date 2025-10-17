import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Home from './Home';
import ThreatDetector from './ThreatDetector';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/predict" element={<ThreatDetector />} />
      </Routes>
    </Router>
  );
}

export default App;
