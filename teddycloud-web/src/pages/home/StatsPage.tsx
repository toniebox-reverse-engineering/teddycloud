import { Breadcrumb } from "antd";
import { useTranslation } from "react-i18next";
import {
  StyledBreadcrumb,
  StyledContent,
  StyledLayout,
  StyledSider,
} from "../../components/StyledComponents";
import { HomeSubNav } from "../../components/HomeSubNav";
import { StatsItem, StatsList, TeddyCloudApi } from "../../api";
import { defaultAPIConfig } from "../../config/defaultApiConfig";
import { useEffect, useState } from "react";

const api = new TeddyCloudApi(defaultAPIConfig());

export const StatsPage = () => {
  const { t } = useTranslation();
  const [stats, setStats] = useState<StatsList | undefined>();
  useEffect(() => {
    const fetchStats = async () => {
      const statsRequest = (await api.statsGet()) as StatsList;
      if (statsRequest?.stats?.length && statsRequest?.stats?.length > 0) {
        setStats(statsRequest);
        console.log("statsRequest", statsRequest);
      }
    };

    fetchStats();
  }, []);

  return (
    <>
      <StyledSider>
        <HomeSubNav />
      </StyledSider>
      <StyledLayout>
        <StyledBreadcrumb>
          <Breadcrumb.Item>{t("home.navigationTitle")}</Breadcrumb.Item>
          <Breadcrumb.Item>{t("home.stats.navigationTitle")}</Breadcrumb.Item>
        </StyledBreadcrumb>
        <StyledContent>
          <h1>{t(`home.stats.title`)}</h1>
        </StyledContent>
      </StyledLayout>
    </>
  );
};
