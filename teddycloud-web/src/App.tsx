import React from "react";
import "./App.css";
import { DatePicker } from "antd";

import { useTranslation } from "react-i18next";

function App() {
  const { t } = useTranslation();
  return (
    <div className="App">
      <header className="App-header">
        <p>{t(`welcome.title`)}</p>
        <p>Sample datepicker from ant design:</p>
        <DatePicker />
      </header>
    </div>
  );
}

export default App;
