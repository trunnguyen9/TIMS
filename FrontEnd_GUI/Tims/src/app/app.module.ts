import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { AppComponent } from './app.component';
import { LoginComponent } from './Components/login/login.component';
import { RegisterComponent } from './Components/register/register.component';
import { AppRoutingModule } from './app-routing.module';
import { ConfigComponent } from './Components/config/config.component';
import { HomeComponent } from './Components/home/home.component';
import { NavbarComponent } from './Components/navbar/navbar.component';
import { StatisticComponent } from './Components/statistic/statistic.component';
import { HttpClientModule } from '@angular/common/http';
import { HttpModule } from '@angular/http';
import { ChartModule } from 'angular-highcharts';
import { FooterComponent } from './Components/footer/footer.component';
import { AboutusComponent } from './Components/aboutus/aboutus.component';

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    RegisterComponent,
    ConfigComponent,
    HomeComponent,
    NavbarComponent,
    StatisticComponent,
    FooterComponent,
    AboutusComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    ReactiveFormsModule,
    HttpClientModule,
    ChartModule,
    HttpModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
